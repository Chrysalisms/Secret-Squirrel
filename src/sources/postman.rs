//! Postman Collection v2.1 source adapter.
//!
//! Parses a [Postman Collection](https://www.postman.com/collection/) v2.1
//! JSON file and extracts all string values that could contain secrets:
//!
//! * Collection-level variables (`variable[].value`)
//! * Request headers (`item[].request.header[].value`)
//! * Request body raw strings (`item[].request.body.raw`)
//! * URL path/query variables (`item[].request.url.variable[].value`)
//!
//! Items can be nested inside folders; the extractor recurses into them.
//!
//! Each extracted string value is emitted as an individual [`Fragment`] whose
//! path encodes its provenance in the form
//! `postman://<collection>/<item>/<field>`.
//!
//! # Example
//!
//! ```rust,no_run
//! use secret_squirrel::sources::postman::PostmanSource;
//! use secret_squirrel::sources::traits::SyncSource as _;
//!
//! let source = PostmanSource::new("My_API.postman_collection.json");
//! for fragment in source.fragments() {
//!     println!("{}", fragment.unwrap().metadata.path);
//! }
//! ```

use std::collections::HashMap;
use std::path::PathBuf;

use bytes::Bytes;
use serde::Deserialize;
use tracing::warn;

use crate::error::{Result, SquirrelError};
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Postman JSON schema (partial)
// ============================================================================

/// Top-level Postman Collection v2.1 document.
#[derive(Debug, Deserialize)]
struct PostmanCollection {
    info: CollectionInfo,
    #[serde(default)]
    variable: Vec<PostmanVariable>,
    #[serde(default)]
    item: Vec<PostmanItem>,
}

/// Collection metadata.
#[derive(Debug, Deserialize)]
struct CollectionInfo {
    name: String,
}

/// A key/value variable (collection-level or URL-level).
#[derive(Debug, Deserialize)]
struct PostmanVariable {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: serde_json::Value,
}

/// A request item or folder containing nested items.
#[derive(Debug, Deserialize)]
struct PostmanItem {
    #[serde(default)]
    name: String,
    /// Present when this item is a request (leaf node).
    request: Option<PostmanRequest>,
    /// Present when this item is a folder (contains nested items).
    #[serde(default)]
    item: Vec<PostmanItem>,
}

/// A single HTTP request inside a Postman item.
#[derive(Debug, Deserialize)]
struct PostmanRequest {
    #[serde(default)]
    header: Vec<PostmanHeader>,
    body: Option<PostmanBody>,
    url: Option<PostmanUrl>,
}

/// A single request header.
#[derive(Debug, Deserialize)]
struct PostmanHeader {
    #[serde(default)]
    value: String,
    #[serde(default)]
    key: String,
}

/// Request body — we only care about `raw`.
#[derive(Debug, Deserialize)]
struct PostmanBody {
    raw: Option<String>,
}

/// Request URL — we extract inline variable values.
#[derive(Debug, Deserialize)]
struct PostmanUrl {
    #[serde(default)]
    variable: Vec<PostmanVariable>,
}

// ============================================================================
// PostmanSource
// ============================================================================

/// A synchronous source that extracts potentially-secret string values from a
/// Postman Collection v2.1 JSON file.
///
/// Construct via [`PostmanSource::new`].
pub struct PostmanSource {
    collection_path: PathBuf,
}

impl PostmanSource {
    /// Create a new `PostmanSource` targeting `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            collection_path: path.into(),
        }
    }
}

impl SyncSource for PostmanSource {
    fn name(&self) -> &str {
        "postman"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        // Parse the collection up front; any parse failure becomes a single
        // error item yielded from the iterator.
        let raw = match std::fs::read(&self.collection_path) {
            Ok(b) => b,
            Err(e) => {
                return Box::new(std::iter::once(Err(SquirrelError::Io(e))));
            }
        };

        let collection: PostmanCollection = match serde_json::from_slice(&raw) {
            Ok(c) => c,
            Err(e) => {
                return Box::new(std::iter::once(Err(SquirrelError::Json(e))));
            }
        };

        let collection_name = collection.info.name.clone();
        let mut fragments: Vec<Result<Fragment>> = Vec::new();

        // ── Collection variables ─────────────────────────────────────────────
        for var in &collection.variable {
            if let Some(s) = json_value_as_string(&var.value) {
                if !s.is_empty() {
                    fragments.push(Ok(make_fragment(
                        &collection_name,
                        "collection",
                        &format!("variable:{}", var.key),
                        s,
                    )));
                }
            }
        }

        // ── Items (recursive) ────────────────────────────────────────────────
        extract_items(&collection.item, &collection_name, &mut fragments);

        Box::new(fragments.into_iter())
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Recursively walk the item tree, appending fragments for every extractable
/// string value.
fn extract_items(items: &[PostmanItem], collection_name: &str, out: &mut Vec<Result<Fragment>>) {
    for item in items {
        // Recurse into folder-style items first.
        if !item.item.is_empty() {
            extract_items(&item.item, collection_name, out);
        }

        let Some(request) = &item.request else {
            continue;
        };

        let item_name = &item.name;

        // ── Headers ─────────────────────────────────────────────────────────
        for hdr in &request.header {
            if !hdr.value.is_empty() {
                out.push(Ok(make_fragment(
                    collection_name,
                    item_name,
                    &format!("header:{}", hdr.key),
                    hdr.value.clone(),
                )));
            }
        }

        // ── Body raw ─────────────────────────────────────────────────────────
        if let Some(body) = &request.body {
            if let Some(raw) = &body.raw {
                if !raw.is_empty() {
                    out.push(Ok(make_fragment(
                        collection_name,
                        item_name,
                        "body:raw",
                        raw.clone(),
                    )));
                }
            }
        }

        // ── URL variables ─────────────────────────────────────────────────────
        if let Some(url) = &request.url {
            for var in &url.variable {
                if let Some(s) = json_value_as_string(&var.value) {
                    if !s.is_empty() {
                        out.push(Ok(make_fragment(
                            collection_name,
                            item_name,
                            &format!("url_var:{}", var.key),
                            s,
                        )));
                    }
                }
            }
        }
    }
}

/// Build a [`Fragment`] whose path is `postman://{collection}/{item}/{field}`.
fn make_fragment(collection_name: &str, item_name: &str, field: &str, content: String) -> Fragment {
    let size = content.len() as u64;
    let path = format!("postman://{collection_name}/{item_name}/{field}");
    let mut attributes = HashMap::new();
    attributes.insert("collection".to_string(), collection_name.to_string());
    attributes.insert("item".to_string(), item_name.to_string());
    attributes.insert("field".to_string(), field.to_string());

    Fragment {
        content: Bytes::from(content.into_bytes()),
        metadata: FragmentMetadata {
            path,
            source_type: SourceType::Postman,
            size,
            attributes,
        },
    }
}

/// Extract a `String` from a [`serde_json::Value`], returning `None` for
/// non-string / null values.
fn json_value_as_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        other => {
            // Log a debug note but don't fail — non-string variable values
            // are valid (numbers, booleans, etc.) but unlikely to be secrets.
            warn!(
                source = "postman",
                value = ?other,
                "Non-string variable value; skipping"
            );
            None
        }
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_collection(dir: &TempDir, name: &str, json: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        path
    }

    // ── name() ───────────────────────────────────────────────────────────────

    #[test]
    fn test_name_returns_postman() {
        let dir = TempDir::new().unwrap();
        let path = write_collection(&dir, "test.json", r#"{"info":{"name":"T"},"item":[]}"#);
        let source = PostmanSource::new(path);
        assert_eq!(source.name(), "postman");
    }

    // ── Parse minimal collection ──────────────────────────────────────────────

    #[test]
    fn test_parse_minimal_collection() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "info": {"name": "My API"},
            "item": []
        }"#;
        let path = write_collection(&dir, "empty.json", json);
        let source = PostmanSource::new(path);
        let fragments: Vec<_> = source.fragments().collect();
        assert!(
            fragments.is_empty(),
            "Empty collection should yield no fragments"
        );
    }

    // ── Collection variables ──────────────────────────────────────────────────

    #[test]
    fn test_extracts_collection_variables() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "info": {"name": "My Collection"},
            "variable": [
                {"key": "API_KEY", "value": "secret123"},
                {"key": "BASE_URL", "value": "https://api.example.com"}
            ],
            "item": []
        }"#;
        let path = write_collection(&dir, "vars.json", json);
        let source = PostmanSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 2, "Should extract 2 collection variables");

        let contents: Vec<String> = fragments
            .iter()
            .map(|f| String::from_utf8(f.content.to_vec()).unwrap())
            .collect();
        assert!(contents.contains(&"secret123".to_string()));
        assert!(contents.contains(&"https://api.example.com".to_string()));
    }

    // ── Request headers ───────────────────────────────────────────────────────

    #[test]
    fn test_extracts_request_headers() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "info": {"name": "My Collection"},
            "item": [
                {
                    "name": "Request 1",
                    "request": {
                        "header": [
                            {"key": "Authorization", "value": "Bearer token123"},
                            {"key": "X-Api-Key", "value": "myapikey"}
                        ],
                        "url": {"variable": []}
                    }
                }
            ]
        }"#;
        let path = write_collection(&dir, "headers.json", json);
        let source = PostmanSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 2, "Should extract 2 header values");

        let paths: Vec<&str> = fragments.iter().map(|f| f.metadata.path.as_str()).collect();
        assert!(
            paths.iter().any(|p| p.contains("header:Authorization")),
            "Should have Authorization header fragment"
        );
    }

    // ── Body raw ─────────────────────────────────────────────────────────────

    #[test]
    fn test_extracts_body_raw() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "info": {"name": "My Collection"},
            "item": [
                {
                    "name": "Login",
                    "request": {
                        "header": [],
                        "body": {"raw": "{\"password\": \"super_secret\"}"},
                        "url": {"variable": []}
                    }
                }
            ]
        }"#;
        let path = write_collection(&dir, "body.json", json);
        let source = PostmanSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1);
        let content = String::from_utf8(fragments[0].content.to_vec()).unwrap();
        assert!(content.contains("super_secret"));
        assert!(fragments[0].metadata.path.contains("body:raw"));
    }

    // ── Nested items (folders) ────────────────────────────────────────────────

    #[test]
    fn test_extracts_nested_folder_items() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "info": {"name": "Nested"},
            "item": [
                {
                    "name": "Auth Folder",
                    "item": [
                        {
                            "name": "Get Token",
                            "request": {
                                "header": [{"key": "X-Secret", "value": "hidden_value"}],
                                "url": {"variable": []}
                            }
                        }
                    ]
                }
            ]
        }"#;
        let path = write_collection(&dir, "nested.json", json);
        let source = PostmanSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1, "Should find the nested item's header");
        let content = String::from_utf8(fragments[0].content.to_vec()).unwrap();
        assert_eq!(content, "hidden_value");
    }

    // ── Source type ───────────────────────────────────────────────────────────

    #[test]
    fn test_fragment_has_postman_source_type() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "info": {"name": "Test"},
            "variable": [{"key": "K", "value": "V"}],
            "item": []
        }"#;
        let path = write_collection(&dir, "st.json", json);
        let source = PostmanSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert!(fragments
            .iter()
            .all(|f| f.metadata.source_type == SourceType::Postman));
    }
}
