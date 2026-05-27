//! Elasticsearch / OpenSearch source adapter.
//!
//! Scrolls through Elasticsearch or OpenSearch index documents and produces
//! [`Fragment`]s from string field values for credential scanning.
//!
//! # Authentication
//!
//! Supports two authentication modes:
//! - **Basic auth**: username + password via `ELASTIC_USER` / `ELASTIC_PASSWORD`
//! - **API key**: `ELASTIC_API_KEY` environment variable or `.api_key()` builder method
//!
//! # Scrolling
//!
//! Uses the Elasticsearch Scroll API to page through large indices without
//! loading all documents into memory simultaneously. Default scroll window
//! is 2 minutes; adjustable via `.scroll_ttl()`.
//!
//! # Example
//!
//! ```rust,ignore
//! use secret_squirrel::sources::elasticsearch::ElasticsearchSourceBuilder;
//!
//! let source = ElasticsearchSourceBuilder::new()
//!     .endpoint("https://my-cluster.es.io:9200")
//!     .api_key("my-api-key")
//!     .indices(vec!["logs-*".into(), "app-events".into()])
//!     .confirmed(true)
//!     .build()
//!     .unwrap();
//! ```

use std::collections::HashMap;

use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::sources::traits::AsyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Elasticsearch API response types
// ============================================================================

/// Top-level search/scroll response.
#[derive(Debug, Deserialize)]
struct EsSearchResponse {
    #[serde(rename = "_scroll_id")]
    scroll_id: Option<String>,
    hits: EsHits,
}

/// The hits container in a search response.
#[derive(Debug, Deserialize)]
struct EsHits {
    hits: Vec<EsHit>,
}

/// A single document hit.
#[derive(Debug, Deserialize)]
struct EsHit {
    #[serde(rename = "_index")]
    index: String,
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "_source")]
    source: Option<serde_json::Value>,
}

// ============================================================================
// Auth mode
// ============================================================================

/// Authentication mode for Elasticsearch.
#[derive(Debug, Clone)]
pub enum EsAuth {
    /// HTTP Basic authentication.
    Basic { username: String, password: String },
    /// API key authentication (passed as `Authorization: ApiKey <key>`).
    ApiKey(String),
    /// No authentication (open / anonymous cluster).
    None,
}

// ============================================================================
// ElasticsearchSource
// ============================================================================

/// Scans Elasticsearch / OpenSearch index documents for credential-like values.
///
/// Construct via [`ElasticsearchSourceBuilder`].
#[derive(Debug)]
pub struct ElasticsearchSource {
    endpoint: String,
    auth: EsAuth,
    /// Index patterns to scan (supports wildcards, e.g. `logs-*`).
    pub indices: Vec<String>,
    /// Maximum documents to fetch per index (default: 50,000).
    pub max_docs: usize,
    /// Scroll window TTL (default: "2m").
    pub scroll_ttl: String,
    client: reqwest::Client,
}

impl ElasticsearchSource {
    fn authed_request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let req = self.client.request(method, url);
        match &self.auth {
            EsAuth::Basic { username, password } => req.basic_auth(username, Some(password)),
            EsAuth::ApiKey(key) => req.header("Authorization", format!("ApiKey {key}")),
            EsAuth::None => req,
        }
    }

    /// Extract string field values from a JSON document recursively.
    fn extract_string_fields(doc: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
        match doc {
            serde_json::Value::String(s) => {
                if !s.is_empty() {
                    out.push((path.to_string(), s.clone()));
                }
            }
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let child_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    Self::extract_string_fields(val, &child_path, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    let child_path = format!("{path}[{i}]");
                    Self::extract_string_fields(item, &child_path, out);
                }
            }
            _ => {} // numbers, bools, null — skip
        }
    }

    fn hit_to_fragments(&self, hit: &EsHit) -> Vec<Fragment> {
        let source = match &hit.source {
            Some(v) => v,
            None => return Vec::new(),
        };

        let mut fields: Vec<(String, String)> = Vec::new();
        Self::extract_string_fields(source, "", &mut fields);

        fields
            .into_iter()
            .filter(|(_, v)| v.len() >= 8) // skip trivially short values
            .map(|(field_path, value)| {
                let path = format!("es://{}/{}/{}/{}", self.endpoint, hit.index, hit.id, field_path);
                let size = value.len() as u64;
                let mut attributes = HashMap::new();
                attributes.insert("index".to_string(), hit.index.clone());
                attributes.insert("doc_id".to_string(), hit.id.clone());
                attributes.insert("field".to_string(), field_path);

                Fragment {
                    content: Bytes::from(value.into_bytes()),
                    metadata: FragmentMetadata {
                        path,
                        source_type: SourceType::Elasticsearch,
                        size,
                        attributes,
                    },
                }
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl AsyncSource for ElasticsearchSource {
    fn name(&self) -> &str {
        "elasticsearch"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        debug!(
            source = "elasticsearch",
            endpoint = %self.endpoint,
            indices = ?self.indices,
            "Starting Elasticsearch scan"
        );

        if self.indices.is_empty() {
            warn!(source = "elasticsearch", "No indices specified — skipping scan");
            return Ok(Vec::new());
        }

        let mut all_fragments = Vec::new();

        for index in &self.indices {
            let search_url = format!(
                "{}/{}/_search?scroll={}&size=100",
                self.endpoint, index, self.scroll_ttl
            );

            let body = serde_json::json!({
                "query": { "match_all": {} },
                "_source": true,
                "sort": ["_doc"]
            });

            let resp = self
                .authed_request(reqwest::Method::POST, &search_url)
                .json(&body)
                .send()
                .await
                .map_err(|e| SquirrelError::Source {
                    src_name: "elasticsearch".into(),
                    reason: format!("Search request failed for index {index}: {e}"),
                })?;

            if !resp.status().is_success() {
                warn!(
                    source = "elasticsearch",
                    index = %index,
                    status = resp.status().as_u16(),
                    "Non-success response — skipping index"
                );
                continue;
            }

            let search_resp: EsSearchResponse =
                resp.json().await.map_err(|e| SquirrelError::Source {
                    src_name: "elasticsearch".into(),
                    reason: format!("JSON parse error for index {index}: {e}"),
                })?;

            let mut docs_fetched = 0usize;
            let mut current_hits = search_resp.hits.hits;
            let mut scroll_id = search_resp.scroll_id;

            loop {
                for hit in &current_hits {
                    let frags = self.hit_to_fragments(hit);
                    all_fragments.extend(frags);
                }
                docs_fetched += current_hits.len();

                if current_hits.is_empty() || docs_fetched >= self.max_docs {
                    break;
                }

                // Advance scroll
                let scroll_url = format!("{}/_search/scroll", self.endpoint);
                let scroll_body = serde_json::json!({
                    "scroll": self.scroll_ttl,
                    "scroll_id": scroll_id
                });

                let scroll_resp = self
                    .authed_request(reqwest::Method::POST, &scroll_url)
                    .json(&scroll_body)
                    .send()
                    .await
                    .map_err(|e| SquirrelError::Source {
                        src_name: "elasticsearch".into(),
                        reason: format!("Scroll request failed: {e}"),
                    })?;

                if !scroll_resp.status().is_success() {
                    break;
                }

                let scroll_result: EsSearchResponse =
                    scroll_resp.json().await.map_err(|e| SquirrelError::Source {
                        src_name: "elasticsearch".into(),
                        reason: format!("Scroll JSON parse error: {e}"),
                    })?;

                scroll_id = scroll_result.scroll_id;
                current_hits = scroll_result.hits.hits;
            }

            debug!(
                source = "elasticsearch",
                index = %index,
                docs = docs_fetched,
                fragments = all_fragments.len(),
                "Finished scanning index"
            );
        }

        Ok(all_fragments)
    }
}

// ============================================================================
// ElasticsearchSourceBuilder
// ============================================================================

/// Builder for [`ElasticsearchSource`].
pub struct ElasticsearchSourceBuilder {
    endpoint: Option<String>,
    auth: EsAuth,
    indices: Vec<String>,
    max_docs: usize,
    scroll_ttl: String,
    confirmed: bool,
}

impl ElasticsearchSourceBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            endpoint: None,
            auth: EsAuth::None,
            indices: Vec::new(),
            max_docs: 50_000,
            scroll_ttl: "2m".to_string(),
            confirmed: false,
        }
    }

    /// Set the cluster endpoint URL (required).
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoint = Some(url.into().trim_end_matches('/').to_string());
        self
    }

    /// Authenticate with an API key.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.auth = EsAuth::ApiKey(key.into());
        self
    }

    /// Authenticate with HTTP Basic credentials.
    pub fn basic_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = EsAuth::Basic {
            username: username.into(),
            password: password.into(),
        };
        self
    }

    /// Index patterns to scan (supports `*` wildcards).
    pub fn indices(mut self, indices: Vec<String>) -> Self {
        self.indices = indices;
        self
    }

    /// Maximum documents to scan per index (default: 50,000).
    pub fn max_docs(mut self, n: usize) -> Self {
        self.max_docs = n;
        self
    }

    /// Scroll TTL string (default: `"2m"`).
    pub fn scroll_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.scroll_ttl = ttl.into();
        self
    }

    /// Acknowledge authorization to scan the target cluster.
    pub fn confirmed(mut self, c: bool) -> Self {
        self.confirmed = c;
        self
    }

    /// Build the [`ElasticsearchSource`].
    pub fn build(self) -> Result<ElasticsearchSource> {
        if !self.confirmed {
            return Err(SquirrelError::Config(
                "ElasticsearchSource: you must call .confirmed(true) to acknowledge \
                 authorization to scan the target cluster"
                    .into(),
            ));
        }
        let endpoint = self.endpoint.ok_or_else(|| {
            SquirrelError::Config("ElasticsearchSource: endpoint URL is required".into())
        })?;

        Ok(ElasticsearchSource {
            endpoint,
            auth: self.auth,
            indices: self.indices,
            max_docs: self.max_docs,
            scroll_ttl: self.scroll_ttl,
            client: reqwest::Client::new(),
        })
    }
}

impl Default for ElasticsearchSourceBuilder {
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

    fn build_source(server_url: &str) -> ElasticsearchSource {
        ElasticsearchSourceBuilder::new()
            .endpoint(server_url)
            .indices(vec!["test-index".into()])
            .confirmed(true)
            .build()
            .unwrap()
    }

    #[test]
    fn test_builder_requires_confirmed() {
        let result = ElasticsearchSourceBuilder::new()
            .endpoint("https://localhost:9200")
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authorization"));
    }

    #[test]
    fn test_builder_requires_endpoint() {
        let result = ElasticsearchSourceBuilder::new().confirmed(true).build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("endpoint"));
    }

    #[test]
    fn test_endpoint_trailing_slash_trimmed() {
        let source = ElasticsearchSourceBuilder::new()
            .endpoint("https://localhost:9200/")
            .confirmed(true)
            .build()
            .unwrap();
        assert!(!source.endpoint.ends_with('/'));
    }

    #[test]
    fn test_name_is_elasticsearch() {
        let source = build_source("https://localhost:9200");
        assert_eq!(source.name(), "elasticsearch");
    }

    #[test]
    fn test_extract_string_fields_flat_object() {
        let doc = serde_json::json!({
            "api_key": "sk_live_abc123",
            "username": "alice",
            "count": 42
        });
        let mut fields = Vec::new();
        ElasticsearchSource::extract_string_fields(&doc, "", &mut fields);
        assert_eq!(fields.len(), 2, "Only string fields should be extracted");
        let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"api_key"));
        assert!(keys.contains(&"username"));
    }

    #[test]
    fn test_extract_string_fields_nested() {
        let doc = serde_json::json!({
            "auth": {
                "token": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",
                "type": "bearer"
            },
            "user": {
                "name": "alice"
            }
        });
        let mut fields = Vec::new();
        ElasticsearchSource::extract_string_fields(&doc, "", &mut fields);
        let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"auth.token"), "Nested field should use dot notation");
        assert!(keys.contains(&"auth.type"));
        assert!(keys.contains(&"user.name"));
    }

    #[test]
    fn test_extract_string_fields_array() {
        let doc = serde_json::json!({
            "tags": ["secret", "production"],
            "keys": ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG"]
        });
        let mut fields = Vec::new();
        ElasticsearchSource::extract_string_fields(&doc, "", &mut fields);
        assert_eq!(fields.len(), 4, "All array string elements should be extracted");
    }

    #[tokio::test]
    async fn test_empty_indices_returns_empty() {
        let source = ElasticsearchSourceBuilder::new()
            .endpoint("https://localhost:9200")
            .indices(vec![]) // no indices
            .confirmed(true)
            .build()
            .unwrap();
        let frags = source.fragments().await.unwrap();
        assert!(frags.is_empty());
    }

    #[tokio::test]
    async fn test_server_error_is_skipped_not_fatal() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("POST", "/test-index/_search?scroll=2m&size=100")
            .with_status(500)
            .with_body(r#"{"error": "internal server error"}"#)
            .create_async()
            .await;

        let source = build_source(&server.url());
        // Server error on one index should not cause fragments() to fail
        let result = source.fragments().await;
        assert!(result.is_ok(), "Server error must be skipped, not fatal");
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_successful_scan_produces_fragments() {
        let mut server = mockito::Server::new_async().await;

        // The source appends ?scroll=2m&size=100 to the search URL
        let _m = server
            .mock("POST", "/test-index/_search?scroll=2m&size=100")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{
                "_scroll_id": "test-scroll-123",
                "hits": {
                    "hits": [
                        {
                            "_index": "test-index",
                            "_id": "doc1",
                            "_source": {
                                "api_key": "sk_live_abcdefghijklmnopqrstuvwxyz123456",
                                "username": "testuser_alice",
                                "count": 42
                            }
                        }
                    ]
                }
            }"#)
            .create_async()
            .await;

        // Scroll endpoint — return empty hits to stop scrolling
        let _m2 = server
            .mock("POST", "/_search/scroll")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"hits": {"hits": []}}"#)
            .create_async()
            .await;

        let source = build_source(&server.url());
        let frags = source.fragments().await.unwrap();

        // Should get fragments for api_key (42 chars) and username (14 chars "testuser_alice")
        assert!(!frags.is_empty(), "Successful scan should produce fragments");
        let api_key_frag = frags.iter().find(|f| {
            f.metadata.attributes.get("field").map(|s| s.as_str()) == Some("api_key")
        });
        assert!(api_key_frag.is_some(), "Must find api_key fragment");
        let content = String::from_utf8(api_key_frag.unwrap().content.to_vec()).unwrap();
        assert!(content.starts_with("sk_live_"));
    }
}

