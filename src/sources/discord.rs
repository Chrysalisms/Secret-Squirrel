//! Discord server source adapter.
//!
//! Scans Discord text channels for messages that may contain accidentally-posted
//! credentials — API keys, passwords, tokens, or connection strings shared in
//! chat.
//!
//! # Authorization
//!
//! This source requires a Discord Bot Token with the following intents/scopes:
//! - `View Channels` — list channels
//! - `Read Message History` — read message history from channels
//!
//! **Important:** You MUST have explicit authorization from your server
//! administrator before scanning Discord messages. The builder enforces this via
//! a required `.confirmed(true)` call.
//!
//! # Rate limiting
//!
//! Discord API has rate limits per endpoint.
//! This adapter inserts a 1.2-second delay between channel requests to stay
//! within limits.
//!
//! # Example
//!
//! ```rust,ignore
//! use secret_squirrel::sources::discord::DiscordSourceBuilder;
//! use secret_squirrel::sources::traits::AsyncSource as _;
//!
//! # tokio_test::block_on(async {
//! let source = DiscordSourceBuilder::new()
//!     .token("my-bot-token")
//!     .guild_id("1234567890")
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
// Discord API response types
// ============================================================================

/// A single Discord channel.
#[derive(Debug, Deserialize)]
struct DiscordChannel {
    id: String,
    name: String,
    #[serde(rename = "type")]
    channel_type: u8,
}

/// A single Discord message.
#[derive(Debug, Deserialize)]
struct DiscordMessage {
    id: String,
    /// The message text.
    #[serde(default)]
    content: String,
    /// ISO8601 timestamp.
    timestamp: String,
}

// ============================================================================
// DiscordSource
// ============================================================================

/// Async source that scans Discord channel message histories for credential
/// fragments.
///
/// Construct via [`DiscordSourceBuilder`].
#[derive(Debug)]
pub struct DiscordSource {
    token: String,
    guild_id: String,
    channel_filter: Vec<String>,
    max_messages_per_channel: usize,
    client: reqwest::Client,
    /// Override the Discord API base URL (used in tests).
    api_base: String,
}

impl DiscordSource {
    /// The inter-channel request delay to respect Discord's rate limits.
    const RATE_LIMIT_DELAY: Duration = Duration::from_millis(1200);

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Build a GET request with the Bot token attached.
    fn authed_get(&self, url: &str) -> reqwest::RequestBuilder {
        self.client
            .get(url)
            .header("User-Agent", "secret-squirrel/0.1.0")
            .header("Authorization", format!("Bot {}", self.token))
    }

    /// Map a Discord error status to a [`SquirrelError`].
    fn discord_error(&self, status: reqwest::StatusCode, url: &str) -> SquirrelError {
        match status.as_u16() {
            401 => SquirrelError::Source {
                src_name: "discord".into(),
                reason: "Discord authentication failed — check bot token".into(),
            },
            403 => SquirrelError::Source {
                src_name: "discord".into(),
                reason: "rate limited or missing required permissions (Read Message History)".into(),
            },
            404 => SquirrelError::Source {
                src_name: "discord".into(),
                reason: format!("not found: {url}"),
            },
            code => SquirrelError::Source {
                src_name: "discord".into(),
                reason: format!("HTTP {code} from {url}"),
            },
        }
    }

    /// Fetch all text channels for the guild.
    async fn list_channels(&self) -> Result<Vec<DiscordChannel>> {
        let url = format!("{}/guilds/{}/channels", self.api_base, self.guild_id);

        let resp = self
            .authed_get(&url)
            .send()
            .await
            .map_err(|e| SquirrelError::Source {
                src_name: "discord".into(),
                reason: format!("guilds channels request failed: {e}"),
            })?;

        if !resp.status().is_success() {
            return Err(self.discord_error(resp.status(), &url));
        }

        let body: Vec<DiscordChannel> =
            resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "discord".into(),
                reason: format!("JSON parse error (channels list): {e}"),
            })?;

        // Filter out non-text channels. Guild Text channels have type = 0.
        let text_channels = body.into_iter().filter(|ch| ch.channel_type == 0);

        // Apply channel filter if specified.
        let channels = if self.channel_filter.is_empty() {
            text_channels.collect()
        } else {
            text_channels
                .filter(|ch| self.channel_filter.contains(&ch.name))
                .collect()
        };

        Ok(channels)
    }

    /// Fetch messages from a single channel.
    async fn channel_messages(&self, channel: &DiscordChannel) -> Vec<Fragment> {
        let url = format!(
            "{}/channels/{}/messages?limit={}",
            self.api_base,
            channel.id,
            // Discord max limit is 100 per request
            self.max_messages_per_channel.min(100)
        );

        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    source = "discord",
                    channel = %channel.name,
                    error = %e,
                    "channel messages request failed; skipping channel"
                );
                return Vec::new();
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "discord",
                channel = %channel.name,
                status = resp.status().as_u16(),
                "Non-success status from channel messages; skipping"
            );
            return Vec::new();
        }

        let messages: Vec<DiscordMessage> = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    source = "discord",
                    channel = %channel.name,
                    error = %e,
                    "JSON parse error from channel messages; skipping"
                );
                return Vec::new();
            }
        };

        debug!(
            source = "discord",
            channel = %channel.name,
            messages = messages.len(),
            "Fetched messages"
        );

        messages
            .into_iter()
            .filter(|msg| !msg.content.is_empty())
            .map(|msg| {
                let size = msg.content.len() as u64;
                let path = format!("discord://{}/{}/{}", self.guild_id, channel.name, msg.id);

                let mut attributes = HashMap::new();
                attributes.insert("guild_id".to_string(), self.guild_id.clone());
                attributes.insert("channel_id".to_string(), channel.id.clone());
                attributes.insert("channel_name".to_string(), channel.name.clone());
                attributes.insert("message_id".to_string(), msg.id.clone());
                attributes.insert("timestamp".to_string(), msg.timestamp.clone());

                Fragment {
                    content: Bytes::from(msg.content.into_bytes()),
                    metadata: FragmentMetadata {
                        path,
                        source_type: SourceType::Discord,
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
impl AsyncSource for DiscordSource {
    fn name(&self) -> &str {
        "discord"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        let channels = self.list_channels().await?;

        debug!(
            source = "discord",
            channel_count = channels.len(),
            "Starting Discord scan"
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
// DiscordSourceBuilder
// ============================================================================

/// Builder for [`DiscordSource`].
///
/// # Authorization acknowledgement
///
/// You **must** call `.confirmed(true)` before [`build`] to acknowledge that
/// you hold explicit authorization to scan Discord messages in your server.
/// This is a deliberate gate to prevent accidental unauthorized scanning.
pub struct DiscordSourceBuilder {
    token: Option<String>,
    guild_id: Option<String>,
    channel_filter: Vec<String>,
    max_messages_per_channel: usize,
    confirmed: bool,
    api_base: Option<String>,
}

impl DiscordSourceBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            token: None,
            guild_id: None,
            channel_filter: Vec::new(),
            max_messages_per_channel: 100,
            confirmed: false,
            api_base: None,
        }
    }

    /// Set the Discord Bot token (required).
    ///
    /// If not set, the builder will look for `DISCORD_TOKEN` in the environment
    /// at build time.
    pub fn token(mut self, t: impl Into<String>) -> Self {
        self.token = Some(t.into());
        self
    }

    /// Set the Discord Guild (Server) ID (required).
    ///
    /// If not set, the builder will look for `DISCORD_GUILD_ID` in the environment.
    pub fn guild_id(mut self, g: impl Into<String>) -> Self {
        self.guild_id = Some(g.into());
        self
    }

    /// Restrict scanning to specific channel names.
    ///
    /// If not called (or called with an empty vec), **all** text channels visible
    /// to the bot are scanned.
    pub fn channel_filter(mut self, channels: Vec<String>) -> Self {
        self.channel_filter = channels;
        self
    }

    /// Maximum number of messages to fetch per channel (default: 100, max: 100).
    pub fn max_messages_per_channel(mut self, n: usize) -> Self {
        self.max_messages_per_channel = n;
        self
    }

    /// Acknowledge that you have authorization to scan Discord messages.
    ///
    /// This **must** be set to `true` or [`build`] will return an error.
    pub fn confirmed(mut self, c: bool) -> Self {
        self.confirmed = c;
        self
    }

    /// Override the Discord API base URL (used in tests).
    pub fn api_base(mut self, url: impl Into<String>) -> Self {
        self.api_base = Some(url.into());
        self
    }

    /// Build the [`DiscordSource`].
    ///
    /// # Errors
    ///
    /// - [`SquirrelError::Config`] if `confirmed` is not `true`.
    /// - [`SquirrelError::Config`] if no token or guild_id is available.
    pub fn build(self) -> Result<DiscordSource> {
        if !self.confirmed {
            return Err(SquirrelError::Config(
                "DiscordSource: you must call .confirmed(true) to acknowledge that you have \
                 authorization to scan Discord messages"
                    .into(),
            ));
        }

        let token = self
            .token
            .or_else(|| std::env::var("DISCORD_TOKEN").ok())
            .ok_or_else(|| {
                SquirrelError::Config(
                    "DiscordSource: a Discord token is required (set via .token() or DISCORD_TOKEN env var)".into(),
                )
            })?;

        let guild_id = self
            .guild_id
            .or_else(|| std::env::var("DISCORD_GUILD_ID").ok())
            .ok_or_else(|| {
                SquirrelError::Config(
                    "DiscordSource: a Discord Guild ID is required (set via .guild_id() or DISCORD_GUILD_ID env var)".into(),
                )
            })?;

        Ok(DiscordSource {
            token,
            guild_id,
            channel_filter: self.channel_filter,
            max_messages_per_channel: self.max_messages_per_channel,
            client: reqwest::Client::new(),
            api_base: self
                .api_base
                .unwrap_or_else(|| "https://discord.com/api/v10".into()),
        })
    }
}

impl Default for DiscordSourceBuilder {
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

    fn build_source(server: &Server) -> DiscordSource {
        DiscordSourceBuilder::new()
            .token("test-token")
            .guild_id("12345")
            .confirmed(true)
            .api_base(server.url())
            .build()
            .expect("builder should succeed")
    }

    // ── Builder requires confirmed = true ─────────────────────────────────────

    #[test]
    fn test_builder_requires_confirmed() {
        let result = DiscordSourceBuilder::new().token("tok").guild_id("123").build();
        assert!(result.is_err());
    }

    // ── Happy path: messages → fragments ─────────────────────────────────────

    #[tokio::test]
    async fn test_messages_become_fragments() {
        let mut server = Server::new_async().await;

        let _m_list = server
            .mock("GET", "/guilds/12345/channels")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":"C001","name":"general","type":0}]"#)
            .create_async()
            .await;

        let _m_hist = server
            .mock("GET", "/channels/C001/messages?limit=100")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[
                {"id": "M1", "content": "Here is the API key: AKIA1234567890ABCDEF", "timestamp": "2024-01-01T00:00:00.000Z"}
            ]"#)
            .create_async()
            .await;

        let source = build_source(&server);
        let fragments = source.fragments().await.expect("should succeed");

        assert_eq!(fragments.len(), 1, "Should produce one fragment per message");
        assert_eq!(fragments[0].metadata.source_type, SourceType::Discord);
        assert!(fragments[0].metadata.path.starts_with("discord://12345/general/M1"));

        let first_content = String::from_utf8(fragments[0].content.to_vec()).unwrap();
        assert!(first_content.contains("AKIA1234567890ABCDEF"));
    }
}
