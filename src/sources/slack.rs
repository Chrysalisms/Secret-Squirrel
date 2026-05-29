//! Slack workspace source adapter.
//!
//! Scans Slack channels for messages that may contain accidentally-posted
//! credentials — API keys, passwords, tokens, or connection strings shared in
//! chat.
//!
//! # Authorization
//!
//! This source requires a Slack OAuth token with the following scopes:
//! - `channels:read` — list public channels
//! - `channels:history` — read message history from public channels
//! - `groups:read` / `groups:history` — for private channels (if required)
//!
//! **Important:** You MUST have explicit authorization from your workspace
//! administrator before scanning Slack messages. The builder enforces this via
//! a required `.confirmed(true)` call.
//!
//! # Rate limiting
//!
//! The Slack `conversations.history` API is Tier 3 (≤ 50 req/min per token).
//! This adapter inserts a 1.2-second delay between channel requests to stay
//! within that limit.
//!
//! # Example
//!
//! ```rust,ignore
//! use secret_squirrel::sources::slack::SlackSourceBuilder;
//! use secret_squirrel::sources::traits::AsyncSource as _;
//!
//! # tokio_test::block_on(async {
//! let source = SlackSourceBuilder::new()
//!     .token("xoxb-my-bot-token")
//!     .confirmed(true)
//!     .build()
//!     .unwrap();
//!
//! let fragments = source.fragments().await.unwrap();
//! # });
//! ```

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::sources::traits::AsyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Slack API response types
// ============================================================================

/// Response from `conversations.list`.
#[derive(Debug, Deserialize)]
struct ConversationsListResponse {
    ok: bool,
    #[serde(default)]
    channels: Vec<SlackChannel>,
    error: Option<String>,
}

/// A single Slack channel.
#[derive(Debug, Deserialize)]
struct SlackChannel {
    id: String,
    name: String,
}

/// Response from `conversations.history`.
#[derive(Debug, Deserialize)]
struct ConversationsHistoryResponse {
    ok: bool,
    #[serde(default)]
    messages: Vec<SlackMessage>,
    error: Option<String>,
}

/// A single Slack message.
#[derive(Debug, Deserialize)]
struct SlackMessage {
    /// The message text (may be absent for non-text message subtypes).
    #[serde(default)]
    text: String,
    /// Unix timestamp as a string (e.g., `"1609459200.000001"`).
    #[serde(default)]
    ts: String,
}

// ============================================================================
// SlackSource
// ============================================================================

/// Async source that scans Slack channel message histories for credential
/// fragments.
///
/// Construct via [`SlackSourceBuilder`].
#[derive(Debug)]
pub struct SlackSource {
    token: String,
    channel_filter: Vec<String>,
    max_messages_per_channel: usize,
    client: reqwest::Client,
    /// Override the Slack API base URL (used in tests).
    api_base: String,
}

impl SlackSource {
    /// The inter-channel request delay required by Slack Tier 3 rate limits.
    const RATE_LIMIT_DELAY: Duration = Duration::from_millis(1200);

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Build a GET request with the Bearer token attached.
    fn authed_get(&self, url: &str) -> reqwest::RequestBuilder {
        self.client
            .get(url)
            .header("User-Agent", "secret-squirrel/0.1.0")
            .header("Authorization", format!("Bearer {}", self.token))
    }

    /// Map a Slack error string to a [`SquirrelError`].
    fn slack_error(&self, error: &str) -> SquirrelError {
        let reason = match error {
            "invalid_auth" | "not_authed" | "token_revoked" => {
                "Slack authentication failed — check token".to_string()
            }
            "missing_scope" => "Slack token is missing required scopes".to_string(),
            "channel_not_found" => "Slack channel not found".to_string(),
            "ratelimited" => "Slack API rate limit exceeded".to_string(),
            other => format!("Slack API error: {other}"),
        };
        SquirrelError::Source {
            src_name: "slack".into(),
            reason,
        }
    }

    /// Fetch all channels (applying the filter if set).
    async fn list_channels(&self) -> Result<Vec<SlackChannel>> {
        let url = format!(
            "{}/conversations.list?limit=200&exclude_archived=true",
            self.api_base
        );

        let resp = self
            .authed_get(&url)
            .send()
            .await
            .map_err(|e| SquirrelError::Source {
                src_name: "slack".into(),
                reason: format!("conversations.list request failed: {e}"),
            })?;

        if resp.status().as_u16() == 401 {
            return Err(SquirrelError::Source {
                src_name: "slack".into(),
                reason: "Slack authentication failed — check token".into(),
            });
        }

        if !resp.status().is_success() {
            return Err(SquirrelError::Source {
                src_name: "slack".into(),
                reason: format!("HTTP {} from conversations.list", resp.status()),
            });
        }

        let body: ConversationsListResponse =
            resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "slack".into(),
                reason: format!("JSON parse error (conversations.list): {e}"),
            })?;

        if !body.ok {
            return Err(self.slack_error(body.error.as_deref().unwrap_or("unknown")));
        }

        // Apply channel filter if specified.
        let channels = if self.channel_filter.is_empty() {
            body.channels
        } else {
            body.channels
                .into_iter()
                .filter(|ch| self.channel_filter.contains(&ch.name))
                .collect()
        };

        Ok(channels)
    }

    /// Fetch messages from a single channel.
    async fn channel_messages(&self, channel: &SlackChannel) -> Vec<Fragment> {
        let url = format!(
            "{}/conversations.history?channel={}&limit={}",
            self.api_base, channel.id, self.max_messages_per_channel
        );

        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    source = "slack",
                    channel = %channel.name,
                    error = %e,
                    "conversations.history request failed; skipping channel"
                );
                return Vec::new();
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "slack",
                channel = %channel.name,
                status = resp.status().as_u16(),
                "Non-success status from conversations.history; skipping"
            );
            return Vec::new();
        }

        let body: ConversationsHistoryResponse = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    source = "slack",
                    channel = %channel.name,
                    error = %e,
                    "JSON parse error from conversations.history; skipping"
                );
                return Vec::new();
            }
        };

        if !body.ok {
            warn!(
                source = "slack",
                channel = %channel.name,
                error = ?body.error,
                "Slack API returned ok=false for conversations.history; skipping"
            );
            return Vec::new();
        }

        debug!(
            source = "slack",
            channel = %channel.name,
            messages = body.messages.len(),
            "Fetched messages"
        );

        body.messages
            .into_iter()
            .filter(|msg| !msg.text.is_empty())
            .map(|msg| {
                let size = msg.text.len() as u64;
                let path = format!("slack://{}/{}", channel.name, msg.ts);

                let mut attributes = HashMap::new();
                attributes.insert("channel_id".to_string(), channel.id.clone());
                attributes.insert("channel_name".to_string(), channel.name.clone());
                attributes.insert("ts".to_string(), msg.ts.clone());

                Fragment {
                    content: Bytes::from(msg.text.into_bytes()),
                    metadata: FragmentMetadata {
                        path,
                        source_type: SourceType::Slack,
                        size,
                        attributes,
                    },
                }
            })
            .collect()
    }
}

// ============================================================================
// AsyncSource implementation
// ============================================================================

#[async_trait::async_trait]
impl AsyncSource for SlackSource {
    fn name(&self) -> &str {
        "slack"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        let channels = self.list_channels().await?;

        debug!(
            source = "slack",
            channel_count = channels.len(),
            "Starting Slack scan"
        );

        let mut all_fragments = Vec::new();

        for (i, channel) in channels.iter().enumerate() {
            let frags = self.channel_messages(channel).await;
            all_fragments.extend(frags);

            // Apply rate-limit delay between channels (but not after the last).
            if i + 1 < channels.len() {
                tokio::time::sleep(Self::RATE_LIMIT_DELAY).await;
            }
        }

        Ok(all_fragments)
    }
}

// ============================================================================
// SlackSourceBuilder
// ============================================================================

/// Builder for [`SlackSource`].
///
/// # Authorization acknowledgement
///
/// You **must** call `.confirmed(true)` before [`build`] to acknowledge that
/// you hold explicit authorization to scan Slack messages in your workspace.
/// This is a deliberate gate to prevent accidental unauthorized scanning.
///
/// # Example
///
/// ```rust,no_run
/// use secret_squirrel::sources::slack::SlackSourceBuilder;
///
/// let source = SlackSourceBuilder::new()
///     .token("xoxb-my-token")
///     .channel_filter(vec!["general".into(), "engineering".into()])
///     .max_messages_per_channel(200)
///     .confirmed(true)
///     .build()
///     .unwrap();
/// ```
pub struct SlackSourceBuilder {
    token: Option<String>,
    channel_filter: Vec<String>,
    max_messages_per_channel: usize,
    confirmed: bool,
    api_base: Option<String>,
}

impl SlackSourceBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            token: None,
            channel_filter: Vec::new(),
            max_messages_per_channel: 100,
            confirmed: false,
            api_base: None,
        }
    }

    /// Set the Slack OAuth token (required).
    ///
    /// If not set, the builder will look for `SLACK_TOKEN` in the environment
    /// at build time.
    pub fn token(mut self, t: impl Into<String>) -> Self {
        self.token = Some(t.into());
        self
    }

    /// Restrict scanning to specific channel names.
    ///
    /// If not called (or called with an empty vec), **all** channels visible
    /// to the token are scanned.
    pub fn channel_filter(mut self, channels: Vec<String>) -> Self {
        self.channel_filter = channels;
        self
    }

    /// Maximum number of messages to fetch per channel (default: 100).
    pub fn max_messages_per_channel(mut self, n: usize) -> Self {
        self.max_messages_per_channel = n;
        self
    }

    /// Acknowledge that you have authorization to scan Slack messages.
    ///
    /// This **must** be set to `true` or [`build`] will return an error.
    pub fn confirmed(mut self, c: bool) -> Self {
        self.confirmed = c;
        self
    }

    /// Override the Slack API base URL (used in tests).
    pub fn api_base(mut self, url: impl Into<String>) -> Self {
        self.api_base = Some(url.into());
        self
    }

    /// Build the [`SlackSource`].
    ///
    /// # Errors
    ///
    /// - [`SquirrelError::Config`] if `confirmed` is not `true`.
    /// - [`SquirrelError::Config`] if no token is available (from `.token()`
    ///   or the `SLACK_TOKEN` environment variable).
    pub fn build(self) -> Result<SlackSource> {
        if !self.confirmed {
            return Err(SquirrelError::Config(
                "SlackSource: you must call .confirmed(true) to acknowledge that you have \
                 authorization to scan Slack messages"
                    .into(),
            ));
        }

        let token = self
            .token
            .or_else(|| std::env::var("SLACK_TOKEN").ok())
            .ok_or_else(|| {
                SquirrelError::Config(
                    "SlackSource: a Slack token is required (set via .token() or SLACK_TOKEN env var)".into(),
                )
            })?;

        Ok(SlackSource {
            token,
            channel_filter: self.channel_filter,
            max_messages_per_channel: self.max_messages_per_channel,
            client: reqwest::Client::new(),
            api_base: self
                .api_base
                .unwrap_or_else(|| "https://slack.com/api".into()),
        })
    }
}

impl Default for SlackSourceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::traits::AsyncSource;
    use mockito::Server;

    fn build_source(server: &Server) -> SlackSource {
        SlackSourceBuilder::new()
            .token("xoxb-test-token")
            .confirmed(true)
            .api_base(server.url())
            .build()
            .expect("builder should succeed")
    }

    // ── name() ───────────────────────────────────────────────────────────────

    #[test]
    fn test_name_returns_slack() {
        let source = SlackSourceBuilder::new()
            .token("tok")
            .confirmed(true)
            .build()
            .unwrap();
        assert_eq!(source.name(), "slack");
    }

    // ── Builder requires confirmed = true ─────────────────────────────────────

    #[test]
    fn test_builder_requires_confirmed() {
        let result = SlackSourceBuilder::new().token("tok").build();
        assert!(
            result.is_err(),
            "build() should fail without confirmed=true"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("authorization"),
            "Error should mention authorization, got: {err}"
        );
    }

    // ── Builder requires token ────────────────────────────────────────────────

    #[test]
    fn test_builder_requires_token() {
        // Make sure SLACK_TOKEN is not set for this test.
        std::env::remove_var("SLACK_TOKEN");

        let result = SlackSourceBuilder::new().confirmed(true).build();
        assert!(result.is_err(), "build() should fail without a token");
    }

    // ── 401 response returns auth error ──────────────────────────────────────

    #[tokio::test]
    async fn test_401_produces_auth_error() {
        let mut server = Server::new_async().await;

        let _m = server
            .mock("GET", "/conversations.list?limit=200&exclude_archived=true")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":false,"error":"invalid_auth"}"#)
            .create_async()
            .await;

        let source = build_source(&server);
        let result = source.fragments().await;
        assert!(result.is_err(), "401 should produce an error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("authentication failed"),
            "Error should mention auth failure, got: {err}"
        );
    }

    // ── Slack API ok=false maps to error ──────────────────────────────────────

    #[tokio::test]
    async fn test_api_ok_false_returns_error() {
        let mut server = Server::new_async().await;

        let _m = server
            .mock("GET", "/conversations.list?limit=200&exclude_archived=true")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":false,"error":"missing_scope"}"#)
            .create_async()
            .await;

        let source = build_source(&server);
        let result = source.fragments().await;
        assert!(result.is_err(), "ok=false should produce an error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("scope"),
            "Error should mention scope, got: {err}"
        );
    }

    // ── Happy path: messages → fragments ─────────────────────────────────────

    #[tokio::test]
    async fn test_messages_become_fragments() {
        let mut server = Server::new_async().await;

        let _m_list = server
            .mock("GET", "/conversations.list?limit=200&exclude_archived=true")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true,"channels":[{"id":"C001","name":"general"}]}"#)
            .create_async()
            .await;

        let _m_hist = server
            .mock("GET", "/conversations.history?channel=C001&limit=100")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{
                "ok": true,
                "messages": [
                    {"text": "Here is the API key: AKIA1234567890ABCDEF", "ts": "1609459200.000001"},
                    {"text": "Never mind", "ts": "1609459201.000002"}
                ]
            }"#)
            .create_async()
            .await;

        let source = build_source(&server);
        let fragments = source.fragments().await.expect("should succeed");

        assert_eq!(
            fragments.len(),
            2,
            "Should produce one fragment per message"
        );
        assert_eq!(fragments[0].metadata.source_type, SourceType::Slack);
        assert!(fragments[0].metadata.path.starts_with("slack://general/"));

        let first_content = String::from_utf8(fragments[0].content.to_vec()).unwrap();
        assert!(first_content.contains("AKIA1234567890ABCDEF"));
    }

    // ── Channel filter ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_channel_filter_applied() {
        let mut server = Server::new_async().await;

        let _m_list = server
            .mock("GET", "/conversations.list?limit=200&exclude_archived=true")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "ok": true,
                "channels": [
                    {"id": "C001", "name": "general"},
                    {"id": "C002", "name": "random"}
                ]
            }"#,
            )
            .create_async()
            .await;

        // Only #general should be requested.
        let _m_hist = server
            .mock("GET", "/conversations.history?channel=C001&limit=100")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true,"messages":[]}"#)
            .create_async()
            .await;

        let source = SlackSourceBuilder::new()
            .token("xoxb-test-token")
            .confirmed(true)
            .channel_filter(vec!["general".into()])
            .api_base(server.url())
            .build()
            .unwrap();

        let fragments = source.fragments().await.expect("should succeed");
        // #random was filtered out, #general has no messages.
        assert!(fragments.is_empty());
    }
}
