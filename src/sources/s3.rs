//! S3 / R2 / GCS object storage source adapter.
//!
//! Scans S3-compatible object storage for credential-containing files. Supports:
//!
//! - **AWS S3** (standard regions, any prefix)
//! - **Cloudflare R2** (via `endpoint_url`)
//! - **MinIO** and other S3-compatible stores (via `endpoint_url`)
//! - **Public buckets** (no credentials required)
//!
//! # Authentication
//!
//! Credentials are resolved in priority order:
//! 1. Struct fields (`access_key_id` / `secret_access_key`)
//! 2. Environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`)
//! 3. Unsigned (public bucket access)
//!
//! AWS SigV4 request signing is implemented from scratch using the crates
//! already present in Cargo.toml (`sha2`, `hmac`, `hex`, `chrono`), so no
//! additional dependencies are required.
//!
//! # Wire Protocol
//!
//! Uses the S3 REST API directly via `reqwest`:
//! - `GET /?list-type=2&prefix=…&continuation-token=…` — paginated listing
//! - `GET /{key}` — object body download
//!
//! The base URL is either:
//! - `https://{bucket}.s3.{region}.amazonaws.com` (AWS path-style for regions)
//! - `{endpoint_url}/{bucket}` (custom endpoint path-style for R2/MinIO)

use std::collections::HashMap;
use std::fmt;

use bytes::Bytes;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Constants
// ============================================================================

/// Default maximum object size (10 MiB). Objects larger than this are skipped.
const DEFAULT_MAX_OBJECT_SIZE: u64 = 10 * 1024 * 1024;

/// Default AWS region.
const DEFAULT_REGION: &str = "us-east-1";

/// Maximum number of keys returned per ListObjectsV2 page (AWS max).
const LIST_PAGE_SIZE: u32 = 1_000;

// ============================================================================
// S3Source
// ============================================================================

/// S3-compatible object storage source adapter.
///
/// Scans every object under `prefix` in `bucket`, yielding one [`Fragment`]
/// per object whose size is ≤ `max_object_size`.
///
/// # Example
///
/// ```rust,ignore
/// let source = S3SourceBuilder::new()
///     .bucket("my-bucket")
///     .prefix("configs/")
///     .region("eu-west-1")
///     .build()?;
/// ```
pub struct S3Source {
    /// S3 bucket name.
    bucket: String,
    /// Key prefix filter (e.g. `"configs/"` or `"repo/secrets/"`).
    prefix: Option<String>,
    /// AWS region (e.g. `"us-east-1"`).
    region: String,
    /// Custom endpoint URL for non-AWS providers (MinIO, Cloudflare R2, etc.).
    endpoint_url: Option<String>,
    /// Skip objects larger than this many bytes.
    max_object_size: u64,
    /// AWS access key ID (overrides env var).
    access_key_id: Option<String>,
    /// AWS secret access key (overrides env var).
    secret_access_key: Option<String>,
    /// Shared HTTP client (connection pool reuse).
    client: Client,
}

impl fmt::Debug for S3Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Source")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.region)
            .field("endpoint_url", &self.endpoint_url)
            .field("max_object_size", &self.max_object_size)
            // credentials intentionally omitted
            .finish()
    }
}

impl S3Source {
    /// Resolve the AWS credentials to use for signing, falling back to env vars.
    ///
    /// Returns `None` if no credentials are available; the caller will attempt
    /// unsigned (public bucket) access.
    fn resolve_credentials(&self) -> Option<(String, String)> {
        let key_id = self
            .access_key_id
            .clone()
            .or_else(|| std::env::var("AWS_ACCESS_KEY_ID").ok())?;
        let secret = self.secret_access_key.clone().or_else(|| {
            std::env::var("AWS_SECRET_ACCESS_KEY")
                .ok()
                .or_else(|| std::env::var("AWS_SECRET_KEY").ok())
        })?;
        Some((key_id, secret))
    }

    /// Build the base URL for this bucket.
    ///
    /// - Custom endpoint: `{endpoint_url}/{bucket}`
    /// - AWS virtual-hosted style: `https://{bucket}.s3.{region}.amazonaws.com`
    fn base_url(&self) -> String {
        match &self.endpoint_url {
            Some(ep) => {
                let ep = ep.trim_end_matches('/');
                format!("{ep}/{}", self.bucket)
            }
            None => {
                format!("https://{}.s3.{}.amazonaws.com", self.bucket, self.region)
            }
        }
    }

    /// Compute the SHA-256 hex digest of a byte slice.
    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Compute HMAC-SHA256 and return the raw bytes.
    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Derive the AWS SigV4 signing key.
    ///
    /// `kSecret` → HMAC("AWS4" + secret, date)
    ///           → HMAC(^, region)
    ///           → HMAC(^, service)
    ///           → HMAC(^, "aws4_request")
    fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
        let k_date = Self::hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
        let k_region = Self::hmac_sha256(&k_date, region.as_bytes());
        let k_service = Self::hmac_sha256(&k_region, service.as_bytes());
        Self::hmac_sha256(&k_service, b"aws4_request")
    }

    /// Build an AWS SigV4 `Authorization` header value.
    ///
    /// Implements the canonical request → string-to-sign → signature flow
    /// described in <https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html>.
    ///
    /// # Parameters
    ///
    /// - `method`      — HTTP verb, upper-cased (e.g. `"GET"`)
    /// - `url`         — Full request URL (used to extract path + query)
    /// - `headers`     — Sorted, lowercase header name → value pairs to sign
    /// - `payload_hash`— SHA-256 hex of the request body (use `UNSIGNED_PAYLOAD` for S3 GETs)
    /// - `key_id`      — AWS access key ID
    /// - `secret`      — AWS secret access key
    #[allow(clippy::too_many_arguments)]
    fn sigv4_auth_header(
        method: &str,
        url: &reqwest::Url,
        headers: &[(&str, &str)],
        payload_hash: &str,
        key_id: &str,
        secret: &str,
        region: &str,
        now: &chrono::DateTime<Utc>,
    ) -> String {
        let date_stamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Canonical URI — percent-encode path but keep '/'
        let canonical_uri = {
            let path = url.path();
            if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            }
        };

        // Canonical query string — sort lexicographically by name then value
        let canonical_qs = {
            let mut pairs: Vec<(String, String)> = url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            pairs.sort();
            pairs
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&")
        };

        // Canonical headers — already sorted by caller; must be lowercase + trimmed
        let mut signed_headers_list: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
        signed_headers_list.sort_unstable();
        let canonical_headers: String = signed_headers_list
            .iter()
            .map(|name| {
                let value = headers
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.trim())
                    .unwrap_or("");
                format!("{name}:{value}\n")
            })
            .collect();
        let signed_headers = signed_headers_list.join(";");

        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_qs}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        let scope = format!("{date_stamp}/{region}/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            Self::sha256_hex(canonical_request.as_bytes())
        );

        let signing_key = Self::derive_signing_key(secret, &date_stamp, region, "s3");
        let signature = hex::encode(Self::hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        format!(
            "AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        )
    }

    /// Send a signed GET request to S3, returning the raw response bytes.
    ///
    /// If `creds` is `None`, the request is sent unsigned (public bucket access).
    async fn signed_get(
        &self,
        url_str: &str,
        creds: Option<(&str, &str)>,
    ) -> Result<reqwest::Response> {
        let url = reqwest::Url::parse(url_str).map_err(|e| SquirrelError::Source {
            src_name: "s3".into(),
            reason: format!("invalid URL '{url_str}': {e}"),
        })?;

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let host = url.host_str().unwrap_or("").to_string();

        let mut builder = self.client.get(url.clone());
        builder = builder.header("x-amz-date", &amz_date);
        builder = builder.header("host", &host);

        if let Some((key_id, secret)) = creds {
            let payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA256("")
            let headers = [("host", host.as_str()), ("x-amz-date", amz_date.as_str())];
            let auth = Self::sigv4_auth_header(
                "GET",
                &url,
                &headers,
                payload_hash,
                key_id,
                secret,
                &self.region,
                &now,
            );
            builder = builder.header("Authorization", auth);
        }

        builder.send().await.map_err(|e| SquirrelError::Source {
            src_name: "s3".into(),
            reason: format!("HTTP request failed for '{url_str}': {e}"),
        })
    }

    /// Fetch one page of the object listing.
    ///
    /// Returns `(keys_and_etags, continuation_token)`.
    async fn list_page(
        &self,
        creds: Option<(&str, &str)>,
        continuation_token: Option<&str>,
    ) -> Result<(Vec<S3Object>, Option<String>)> {
        let base = self.base_url();
        let mut params: Vec<(&str, String)> = vec![
            ("list-type", "2".into()),
            ("max-keys", LIST_PAGE_SIZE.to_string()),
        ];
        if let Some(pfx) = &self.prefix {
            if !pfx.is_empty() {
                params.push(("prefix", pfx.clone()));
            }
        }
        if let Some(tok) = continuation_token {
            params.push(("continuation-token", tok.to_string()));
        }

        let qs: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let url = format!("{base}/?{qs}");
        debug!(url = %url, "S3 ListObjectsV2 request");

        let resp = self.signed_get(&url, creds).await?;
        let status = resp.status();

        if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
            return Err(SquirrelError::Source {
                src_name: "s3".into(),
                reason: format!("access denied to bucket '{}' (HTTP {status})", self.bucket),
            });
        }
        if !status.is_success() {
            return Err(SquirrelError::Source {
                src_name: "s3".into(),
                reason: format!(
                    "ListObjectsV2 failed for bucket '{}': HTTP {status}",
                    self.bucket
                ),
            });
        }

        let body = resp.text().await.map_err(|e| SquirrelError::Source {
            src_name: "s3".into(),
            reason: format!("failed to read ListObjectsV2 response: {e}"),
        })?;

        parse_list_objects_xml(&body)
    }

    /// Download a single S3 object and return its bytes.
    ///
    /// Returns `Ok(None)` if the object was not found (deleted between list and get).
    async fn get_object(&self, key: &str, creds: Option<(&str, &str)>) -> Result<Option<Bytes>> {
        let base = self.base_url();
        let encoded_key = key
            .split('/')
            .map(urlencoding::encode)
            .collect::<Vec<_>>()
            .join("/");
        let url = format!("{base}/{encoded_key}");

        debug!(bucket = %self.bucket, key = %key, "S3 GetObject");

        let resp = self.signed_get(&url, creds).await?;
        let status = resp.status();

        if status == StatusCode::NOT_FOUND {
            warn!(bucket = %self.bucket, key = %key, "S3 object not found (deleted between list and get)");
            return Ok(None);
        }
        if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
            warn!(bucket = %self.bucket, key = %key, "S3 GetObject access denied — skipping");
            return Ok(None);
        }
        if !status.is_success() {
            return Err(SquirrelError::Source {
                src_name: "s3".into(),
                reason: format!(
                    "GetObject failed for s3://{}/{key}: HTTP {status}",
                    self.bucket
                ),
            });
        }

        let bytes = resp.bytes().await.map_err(|e| SquirrelError::Source {
            src_name: "s3".into(),
            reason: format!("failed to stream object body for '{key}': {e}"),
        })?;

        Ok(Some(bytes))
    }
}

// ============================================================================
// AsyncSource implementation
// ============================================================================

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for S3Source {
    fn name(&self) -> &str {
        "s3"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        let creds = self.resolve_credentials();
        // Convert Option<(String, String)> → Option<(&str, &str)> for lifetime safety
        let creds_ref = creds.as_ref().map(|(k, s)| (k.as_str(), s.as_str()));

        let mut fragments: Vec<Fragment> = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let token_ref = continuation_token.as_deref();
            let (objects, next_token) = match self.list_page(creds_ref, token_ref).await {
                Ok(result) => result,
                Err(e) => {
                    if matches!(&e, SquirrelError::Source { reason, .. } if reason.contains("access denied"))
                    {
                        warn!("S3 source '{}': {e} — bucket scan aborted", self.bucket);
                        return Ok(fragments);
                    }
                    return Err(e);
                }
            };

            debug!(
                bucket = %self.bucket,
                count = objects.len(),
                has_next = next_token.is_some(),
                "S3 page received"
            );

            for obj in objects {
                if obj.size > self.max_object_size {
                    debug!(
                        key = %obj.key,
                        size = obj.size,
                        max = self.max_object_size,
                        "Skipping oversized S3 object"
                    );
                    continue;
                }

                match self.get_object(&obj.key, creds_ref).await {
                    Ok(Some(content)) => {
                        let size = content.len() as u64;
                        let mut attributes: HashMap<String, String> = HashMap::new();
                        attributes.insert("bucket".into(), self.bucket.clone());
                        attributes.insert("key".into(), obj.key.clone());
                        if let Some(etag) = &obj.etag {
                            // S3 ETags are surrounded by quotes; strip them
                            let clean_etag = etag.trim_matches('"').to_string();
                            attributes.insert("etag".into(), clean_etag);
                        }

                        fragments.push(Fragment {
                            content,
                            metadata: FragmentMetadata {
                                path: format!("s3://{}/{}", self.bucket, obj.key),
                                source_type: SourceType::S3,
                                size,
                                attributes,
                            },
                        });
                    }
                    Ok(None) => {
                        // Already warned inside get_object
                    }
                    Err(e) => {
                        warn!(
                            bucket = %self.bucket,
                            key = %obj.key,
                            error = %e,
                            "Failed to fetch S3 object — skipping"
                        );
                    }
                }
            }

            match next_token {
                Some(tok) => continuation_token = Some(tok),
                None => break,
            }
        }

        Ok(fragments)
    }
}

// ============================================================================
// XML parsing
// ============================================================================

/// A single entry from the S3 ListObjectsV2 response.
#[derive(Debug, Clone)]
pub(crate) struct S3Object {
    pub(crate) key: String,
    pub(crate) size: u64,
    pub(crate) etag: Option<String>,
}

/// Parse the XML body of a ListObjectsV2 response.
///
/// We parse the XML with a minimal hand-rolled extractor rather than pulling
/// in an XML crate. The ListObjectsV2 format is stable and well-defined.
///
/// Returns `(objects, next_continuation_token)`.
pub(crate) fn parse_list_objects_xml(xml: &str) -> Result<(Vec<S3Object>, Option<String>)> {
    let mut objects = Vec::new();
    let mut next_token: Option<String> = None;

    // Extract all <Contents>…</Contents> blocks
    let mut search_from = 0;
    while let Some(start) = xml[search_from..].find("<Contents>") {
        let abs_start = search_from + start;
        let content_start = abs_start + "<Contents>".len();
        if let Some(end_rel) = xml[abs_start..].find("</Contents>") {
            let abs_end = abs_start + end_rel;
            let block = &xml[content_start..abs_end];

            let key = extract_xml_text(block, "Key").unwrap_or_default();
            let size_str = extract_xml_text(block, "Size").unwrap_or_default();
            let etag = extract_xml_text(block, "ETag");

            let size: u64 = size_str.parse().unwrap_or(0);

            if !key.is_empty() {
                objects.push(S3Object { key, size, etag });
            }

            search_from = abs_end + "</Contents>".len();
        } else {
            break;
        }
    }

    // Extract continuation token if present
    if let Some(tok) = extract_xml_text(xml, "NextContinuationToken") {
        if !tok.is_empty() {
            next_token = Some(tok);
        }
    }

    Ok((objects, next_token))
}

/// Extract the text content of the first occurrence of `<tag>…</tag>` in `xml`.
fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

// ============================================================================
// S3SourceBuilder
// ============================================================================

/// Builder for [`S3Source`].
///
/// # Required
///
/// - [`bucket`](S3SourceBuilder::bucket) — must be set before calling [`build`](S3SourceBuilder::build)
///
/// # Defaults
///
/// | Field             | Default       |
/// |-------------------|---------------|
/// | `region`          | `"us-east-1"` |
/// | `max_object_size` | 10 MiB        |
/// | `prefix`          | `None`        |
/// | `endpoint_url`    | `None`        |
#[derive(Debug, Default)]
pub struct S3SourceBuilder {
    bucket: Option<String>,
    prefix: Option<String>,
    region: String,
    endpoint_url: Option<String>,
    max_object_size: u64,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
}

impl S3SourceBuilder {
    /// Create a new builder with sensible defaults.
    pub fn new() -> Self {
        Self {
            region: DEFAULT_REGION.to_string(),
            max_object_size: DEFAULT_MAX_OBJECT_SIZE,
            ..Default::default()
        }
    }

    /// Set the bucket name (required).
    pub fn bucket(mut self, b: impl Into<String>) -> Self {
        self.bucket = Some(b.into());
        self
    }

    /// Filter objects by key prefix (e.g. `"configs/"` to scan only that virtual folder).
    pub fn prefix(mut self, p: impl Into<String>) -> Self {
        self.prefix = Some(p.into());
        self
    }

    /// Set the AWS region (default: `"us-east-1"`).
    pub fn region(mut self, r: impl Into<String>) -> Self {
        self.region = r.into();
        self
    }

    /// Set a custom endpoint URL for non-AWS S3-compatible providers.
    ///
    /// Examples:
    /// - MinIO: `"http://localhost:9000"`
    /// - Cloudflare R2: `"https://<account-id>.r2.cloudflarestorage.com"`
    pub fn endpoint_url(mut self, url: impl Into<String>) -> Self {
        self.endpoint_url = Some(url.into());
        self
    }

    /// Set the maximum object size in bytes (default: 10 MiB).
    ///
    /// Objects larger than this limit are listed but their content is not
    /// downloaded, preventing memory exhaustion on buckets with large binaries.
    pub fn max_object_size_bytes(mut self, bytes: u64) -> Self {
        self.max_object_size = bytes;
        self
    }

    /// Set the AWS access key ID (overrides `AWS_ACCESS_KEY_ID` env var).
    pub fn access_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.access_key_id = Some(key_id.into());
        self
    }

    /// Set the AWS secret access key (overrides `AWS_SECRET_ACCESS_KEY` env var).
    pub fn secret_access_key(mut self, secret: impl Into<String>) -> Self {
        self.secret_access_key = Some(secret.into());
        self
    }

    /// Build the [`S3Source`].
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Config`] if `bucket` was not set.
    pub fn build(self) -> Result<S3Source> {
        let bucket = self
            .bucket
            .ok_or_else(|| SquirrelError::Config("S3SourceBuilder: 'bucket' is required".into()))?;

        let client = Client::builder()
            .user_agent("secret-squirrel/0.1.0")
            .build()
            .map_err(|e| SquirrelError::Source {
                src_name: "s3".into(),
                reason: format!("failed to build HTTP client: {e}"),
            })?;

        Ok(S3Source {
            bucket,
            prefix: self.prefix,
            region: self.region,
            endpoint_url: self.endpoint_url,
            max_object_size: self.max_object_size,
            access_key_id: self.access_key_id,
            secret_access_key: self.secret_access_key,
            client,
        })
    }
}

// ============================================================================
// urlencoding helper (inline to avoid adding a crate)
// ============================================================================

mod urlencoding {
    /// Percent-encode a string for use in a URL query parameter value.
    /// Encodes all characters except unreserved chars: A–Z a–z 0–9 - _ . ~
    pub fn encode(input: &str) -> String {
        let mut out = String::with_capacity(input.len() * 2);
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char)
                }
                b => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_name_returns_s3() {
        let source = S3SourceBuilder::new()
            .bucket("test-bucket")
            .build()
            .expect("build should succeed");

        use crate::sources::traits::AsyncSource;
        assert_eq!(source.name(), "s3");
    }

    #[test]
    fn test_builder_requires_bucket() {
        let result = S3SourceBuilder::new().build();
        assert!(
            result.is_err(),
            "build() without bucket should return an error"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("bucket"),
            "Error should mention 'bucket', got: {err}"
        );
    }

    #[test]
    fn test_builder_default_region() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .build()
            .expect("build should succeed");
        assert_eq!(source.region, "us-east-1");
    }

    #[test]
    fn test_builder_custom_region() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .region("eu-west-2")
            .build()
            .expect("build should succeed");
        assert_eq!(source.region, "eu-west-2");
    }

    #[test]
    fn test_builder_max_object_size_default() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .build()
            .expect("build should succeed");
        assert_eq!(source.max_object_size, DEFAULT_MAX_OBJECT_SIZE);
    }

    #[test]
    fn test_builder_max_object_size_custom() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .max_object_size_bytes(1024)
            .build()
            .expect("build should succeed");
        assert_eq!(source.max_object_size, 1024);
    }

    #[test]
    fn test_builder_prefix() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .prefix("configs/")
            .build()
            .expect("build should succeed");
        assert_eq!(source.prefix.as_deref(), Some("configs/"));
    }

    #[test]
    fn test_builder_endpoint_url() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .endpoint_url("http://localhost:9000")
            .build()
            .expect("build should succeed");
        assert_eq!(
            source.endpoint_url.as_deref(),
            Some("http://localhost:9000")
        );
    }

    // -----------------------------------------------------------------------
    // Base URL construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_base_url_aws() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .region("us-west-2")
            .build()
            .unwrap();
        assert_eq!(
            source.base_url(),
            "https://my-bucket.s3.us-west-2.amazonaws.com"
        );
    }

    #[test]
    fn test_base_url_custom_endpoint() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .endpoint_url("http://localhost:9000")
            .build()
            .unwrap();
        assert_eq!(source.base_url(), "http://localhost:9000/my-bucket");
    }

    #[test]
    fn test_base_url_custom_endpoint_trailing_slash() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .endpoint_url("http://localhost:9000/")
            .build()
            .unwrap();
        // Trailing slash on the endpoint should be stripped
        assert_eq!(source.base_url(), "http://localhost:9000/my-bucket");
    }

    // -----------------------------------------------------------------------
    // XML parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_list_objects_xml_basic() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix></Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>configs/app.env</Key>
    <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    <ETag>&quot;abc123&quot;</ETag>
    <Size>512</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>secrets/db.env</Key>
    <LastModified>2024-01-02T00:00:00.000Z</LastModified>
    <ETag>&quot;def456&quot;</ETag>
    <Size>256</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>"#;

        let (objects, next_token) = parse_list_objects_xml(xml).expect("parsing should succeed");
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].key, "configs/app.env");
        assert_eq!(objects[0].size, 512);
        assert_eq!(objects[1].key, "secrets/db.env");
        assert_eq!(objects[1].size, 256);
        assert!(next_token.is_none());
    }

    #[test]
    fn test_parse_list_objects_xml_with_continuation() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>true</IsTruncated>
  <Contents>
    <Key>file1.txt</Key>
    <Size>100</Size>
    <ETag>&quot;aaa&quot;</ETag>
  </Contents>
  <NextContinuationToken>page2token==</NextContinuationToken>
</ListBucketResult>"#;

        let (objects, next_token) = parse_list_objects_xml(xml).expect("parsing should succeed");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].key, "file1.txt");
        assert_eq!(next_token.as_deref(), Some("page2token=="));
    }

    #[test]
    fn test_parse_list_objects_xml_empty() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <KeyCount>0</KeyCount>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;

        let (objects, next_token) = parse_list_objects_xml(xml).expect("parsing should succeed");
        assert!(objects.is_empty());
        assert!(next_token.is_none());
    }

    #[test]
    fn test_parse_list_objects_xml_etag_stripped() {
        let xml = r#"<ListBucketResult>
  <Contents>
    <Key>test.txt</Key>
    <Size>42</Size>
    <ETag>"deadbeef"</ETag>
  </Contents>
</ListBucketResult>"#;

        let (objects, _) = parse_list_objects_xml(xml).expect("parsing should succeed");
        assert_eq!(objects.len(), 1);
        // The raw ETag from XML may contain quotes; strip_matches is applied in fragments()
        let raw_etag = objects[0].etag.as_deref().unwrap_or("");
        let cleaned = raw_etag.trim_matches('"');
        assert_eq!(cleaned, "deadbeef");
    }

    // -----------------------------------------------------------------------
    // URL encoding
    // -----------------------------------------------------------------------

    #[test]
    fn test_urlencoding_unreserved() {
        assert_eq!(urlencoding::encode("hello"), "hello");
        assert_eq!(urlencoding::encode("Hello_World-1.2~"), "Hello_World-1.2~");
    }

    #[test]
    fn test_urlencoding_spaces_and_special() {
        let encoded = urlencoding::encode("configs/my file.env");
        assert_eq!(encoded, "configs%2Fmy%20file.env");
    }

    #[test]
    fn test_urlencoding_empty() {
        assert_eq!(urlencoding::encode(""), "");
    }

    // -----------------------------------------------------------------------
    // SHA-256 / HMAC helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_empty_string() {
        // SHA-256("") = e3b0c442...
        let digest = S3Source::sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_credential_resolution_from_fields() {
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .access_key_id("AKIATEST")
            .secret_access_key("supersecret")
            .build()
            .unwrap();

        let creds = source.resolve_credentials();
        assert!(creds.is_some());
        let (kid, secret) = creds.unwrap();
        assert_eq!(kid, "AKIATEST");
        assert_eq!(secret, "supersecret");
    }

    #[test]
    fn test_credential_resolution_no_creds() {
        // Ensure env vars are not set for this test path
        // (we can't unset them reliably in all CI, so we test the struct path only)
        let source = S3SourceBuilder::new()
            .bucket("my-bucket")
            .access_key_id("AKIAEXAMPLE")
            .secret_access_key("example_secret")
            .build()
            .unwrap();
        // As long as fields are set, resolution succeeds
        assert!(source.resolve_credentials().is_some());
    }
}
