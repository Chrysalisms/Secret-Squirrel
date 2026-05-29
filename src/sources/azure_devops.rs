//! Azure DevOps Services source adapter.
//!
//! Scans repositories, pipeline YAML definitions, pipeline variable groups,
//! and wiki pages in an Azure DevOps organization using the Azure DevOps REST
//! API (api-version 7.1).
//!
//! # Scanning strategy
//!
//! 1. If [`AzureDevOpsSource::project`] is `Some`, scan only that project.
//!    Otherwise list all projects in the organization.
//! 2. For each project, enumerate Git repositories and walk their file trees.
//! 3. If `scan_variable_groups` is enabled, fetch all pipeline variable groups
//!    and emit a Fragment per group containing all non-secret variable values.
//! 4. If `scan_pipelines` is enabled, fetch pipeline YAML definitions.
//! 5. If `scan_wikis` is enabled, fetch wiki pages.
//!
//! # Authentication
//!
//! Azure DevOps uses HTTP Basic auth with an empty username and a Personal
//! Access Token (PAT) as the password. The `Authorization` header value is:
//!
//! ```text
//! Authorization: Basic base64(":" + PAT)
//! ```
//!
//! Supply the PAT via `AZURE_DEVOPS_TOKEN` env-var or [`AzureDevOpsSource::new`].

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Azure DevOps API response types
// ============================================================================

/// Paginated list wrapper used by most Azure DevOps list endpoints.
#[derive(Debug, Deserialize)]
struct AdoList<T> {
    value: Vec<T>,
    #[serde(default, rename = "count")]
    _count: u64,
}

/// A project returned by `GET /{org}/_apis/projects`.
#[derive(Debug, Deserialize)]
struct AdoProject {
    id: String,
    name: String,
}

/// A Git repository returned by `GET /{org}/{project}/_apis/git/repositories`.
#[derive(Debug, Deserialize)]
struct AdoRepo {
    id: String,
    name: String,
    #[serde(rename = "defaultBranch")]
    default_branch: Option<String>,
}

/// A file tree item from `GET …/items?recursionLevel=full`.
#[derive(Debug, Deserialize)]
struct AdoItem {
    path: String,
    #[serde(rename = "isFolder", default)]
    is_folder: bool,
    #[serde(rename = "objectId")]
    object_id: Option<String>,
    #[serde(rename = "contentMetadata")]
    content_metadata: Option<AdoContentMetadata>,
}

/// Content metadata embedded in an item.
#[derive(Debug, Deserialize)]
struct AdoContentMetadata {
    #[serde(rename = "contentType")]
    content_type: Option<String>,
}

/// A blob object from `GET …/blobs/{blobId}`.
// The blob endpoint returns raw bytes directly, not JSON, so this is only
// used for the metadata endpoint.
#[derive(Debug, Deserialize)]
struct AdoBlob {
    #[serde(rename = "objectId")]
    object_id: String,
}

/// A variable group returned by `GET /{org}/{project}/_apis/distributedtask/variablegroups`.
#[derive(Debug, Deserialize)]
struct AdoVariableGroup {
    id: u64,
    name: String,
    variables: HashMap<String, AdoVariable>,
}

/// A single variable inside a variable group.
#[derive(Debug, Deserialize)]
struct AdoVariable {
    value: Option<String>,
    #[serde(rename = "isSecret", default)]
    is_secret: bool,
}

/// A pipeline definition returned by `GET /{org}/{project}/_apis/pipelines`.
#[derive(Debug, Deserialize)]
struct AdoPipeline {
    id: u64,
    name: String,
}

/// A wiki page tree entry (simplified — the wiki tree API returns a richer object).
#[derive(Debug, Deserialize)]
struct AdoWikiPage {
    path: String,
    #[serde(rename = "isParentPage", default)]
    is_parent: bool,
    content: Option<String>,
}

// ============================================================================
// AzureDevOpsSource
// ============================================================================

/// Async source that scans Azure DevOps Services for credential fragments.
///
/// Construct with [`AzureDevOpsSource::new`] and configure with the builder
/// methods:
///
/// ```rust,no_run
/// # use secret_squirrel::sources::azure_devops::AzureDevOpsSource;
/// let source = AzureDevOpsSource::new("myorg", "my-pat-token")
///     .with_project("my-project")
///     .with_variable_groups();
/// ```
pub struct AzureDevOpsSource {
    client: reqwest::Client,
    organization: String,
    project: Option<String>,
    token: String,
    host: String,
    scan_pipelines: bool,
    scan_variable_groups: bool,
    scan_wikis: bool,
    max_depth: usize,
    max_file_size: u64,
}

impl AzureDevOpsSource {
    /// Default maximum file size (1 MiB).
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024;

    /// Azure DevOps REST API version used in all requests.
    const API_VERSION: &'static str = "7.1";

    /// Create a new source for the given `organization`.
    ///
    /// `token` is a Personal Access Token. It is sent as HTTP Basic auth with
    /// an empty username (`Authorization: Basic base64(":" + token)`).
    pub fn new(organization: impl Into<String>, token: impl Into<String>) -> Self {
        let token_str = token.into();
        // Fall back to env-var if caller passed an empty string.
        let resolved_token = if token_str.is_empty() {
            std::env::var("AZURE_DEVOPS_TOKEN").unwrap_or_default()
        } else {
            token_str
        };

        Self {
            client: reqwest::Client::new(),
            organization: organization.into(),
            project: None,
            token: resolved_token,
            host: "https://dev.azure.com".into(),
            scan_pipelines: false,
            scan_variable_groups: false,
            scan_wikis: false,
            max_depth: 0,
            max_file_size: Self::DEFAULT_MAX_FILE_SIZE,
        }
    }

    /// Limit scanning to a single project (default: all projects).
    pub fn with_project(mut self, project: &str) -> Self {
        self.project = Some(project.to_owned());
        self
    }

    /// Enable pipeline variable group scanning (high-value secrets source).
    pub fn with_variable_groups(mut self) -> Self {
        self.scan_variable_groups = true;
        self
    }

    /// Enable pipeline YAML definition scanning.
    pub fn with_pipelines(mut self) -> Self {
        self.scan_pipelines = true;
        self
    }

    /// Enable wiki page scanning.
    pub fn with_wikis(mut self) -> Self {
        self.scan_wikis = true;
        self
    }

    /// Override the Azure DevOps host (default: `https://dev.azure.com`).
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// Set the maximum depth for commit/item traversal (0 = unlimited).
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the `Authorization: Basic base64(:PAT)` header value.
    fn auth_header(&self) -> String {
        let credential = format!(":{}", self.token);
        format!("Basic {}", BASE64.encode(credential.as_bytes()))
    }

    /// Attach authentication and the required headers to a GET request.
    fn authed_get(&self, url: &str) -> reqwest::RequestBuilder {
        self.client
            .get(url)
            .header("User-Agent", "secret-squirrel/0.1.0")
            .header("Authorization", self.auth_header())
            .header("Accept", "application/json")
    }

    /// Convert an HTTP status code into a [`SquirrelError`].
    fn status_error(&self, status: reqwest::StatusCode, url: &str) -> SquirrelError {
        match status.as_u16() {
            401 => SquirrelError::Source {
                src_name: "azure_devops".into(),
                reason: "authentication failed — check PAT (AZURE_DEVOPS_TOKEN)".into(),
            },
            403 => SquirrelError::Source {
                src_name: "azure_devops".into(),
                reason: "rate limited or forbidden — check PAT scopes".into(),
            },
            404 => SquirrelError::Source {
                src_name: "azure_devops".into(),
                reason: format!("not found: {url}"),
            },
            code => SquirrelError::Source {
                src_name: "azure_devops".into(),
                reason: format!("HTTP {code} from {url}"),
            },
        }
    }

    /// Append `?api-version=7.1` (or `&api-version=7.1` if query already exists).
    fn versioned(&self, url: &str) -> String {
        if url.contains('?') {
            format!("{url}&api-version={}", Self::API_VERSION)
        } else {
            format!("{url}?api-version={}", Self::API_VERSION)
        }
    }

    // -----------------------------------------------------------------------
    // Project enumeration
    // -----------------------------------------------------------------------

    /// List all projects in the organization.
    async fn list_projects(&self) -> Result<Vec<AdoProject>> {
        let url = self.versioned(&format!("{}/{}/_apis/projects", self.host, self.organization));
        let resp = self.authed_get(&url).send().await.map_err(|e| {
            SquirrelError::Source {
                src_name: "azure_devops".into(),
                reason: e.to_string(),
            }
        })?;

        if !resp.status().is_success() {
            return Err(self.status_error(resp.status(), &url));
        }

        let body: AdoList<AdoProject> = resp.json().await.map_err(|e| SquirrelError::Source {
            src_name: "azure_devops".into(),
            reason: format!("JSON parse error listing projects: {e}"),
        })?;

        Ok(body.value)
    }

    // -----------------------------------------------------------------------
    // Repository enumeration
    // -----------------------------------------------------------------------

    /// List all Git repositories in a project.
    async fn list_repos(&self, project: &str) -> Result<Vec<AdoRepo>> {
        let url = self.versioned(&format!(
            "{}/{}/{}/_apis/git/repositories",
            self.host, self.organization, project
        ));
        let resp = self.authed_get(&url).send().await.map_err(|e| {
            SquirrelError::Source {
                src_name: "azure_devops".into(),
                reason: e.to_string(),
            }
        })?;

        if !resp.status().is_success() {
            return Err(self.status_error(resp.status(), &url));
        }

        let body: AdoList<AdoRepo> = resp.json().await.map_err(|e| SquirrelError::Source {
            src_name: "azure_devops".into(),
            reason: format!("JSON parse error listing repos in {project}: {e}"),
        })?;

        Ok(body.value)
    }

    // -----------------------------------------------------------------------
    // File tree walking
    // -----------------------------------------------------------------------

    /// Fetch the full recursive file tree for a repository.
    async fn list_items(&self, project: &str, repo_id: &str, branch: &str) -> Result<Vec<AdoItem>> {
        let url = self.versioned(&format!(
            "{}/{}/{}/_apis/git/repositories/{}/items?recursionLevel=full&versionDescriptor.version={}&versionDescriptor.versionType=branch",
            self.host, self.organization, project, repo_id, branch
        ));

        let resp = self.authed_get(&url).send().await.map_err(|e| {
            SquirrelError::Source {
                src_name: "azure_devops".into(),
                reason: e.to_string(),
            }
        })?;

        if !resp.status().is_success() {
            return Err(self.status_error(resp.status(), &url));
        }

        let body: AdoList<AdoItem> = resp.json().await.map_err(|e| SquirrelError::Source {
            src_name: "azure_devops".into(),
            reason: format!("JSON parse error listing items for repo {repo_id}: {e}"),
        })?;

        Ok(body.value)
    }

    /// Fetch the raw bytes of a blob by its object ID.
    async fn fetch_blob(
        &self,
        project: &str,
        repo_id: &str,
        blob_id: &str,
        path: &str,
    ) -> Option<Bytes> {
        // The blob download endpoint returns raw bytes when Accept is set to
        // application/octet-stream. JSON accept header is used for metadata.
        let url = self.versioned(&format!(
            "{}/{}/{}/_apis/git/repositories/{}/blobs/{}",
            self.host, self.organization, project, repo_id, blob_id
        ));

        let resp = match self
            .client
            .get(&url)
            .header("User-Agent", "secret-squirrel/0.1.0")
            .header("Authorization", self.auth_header())
            .header("Accept", "application/octet-stream")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    source = "azure_devops",
                    project,
                    repo = repo_id,
                    path,
                    error = %e,
                    "HTTP request failed; skipping file"
                );
                return None;
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "azure_devops",
                project,
                repo = repo_id,
                path,
                status = resp.status().as_u16(),
                "Non-success fetching blob; skipping"
            );
            return None;
        }

        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    source = "azure_devops",
                    project,
                    repo = repo_id,
                    path,
                    error = %e,
                    "Failed to read blob bytes; skipping"
                );
                return None;
            }
        };

        if bytes.len() as u64 > self.max_file_size {
            debug!(
                source = "azure_devops",
                project,
                repo = repo_id,
                path,
                size = bytes.len(),
                max = self.max_file_size,
                "Skipping oversized file"
            );
            return None;
        }

        Some(bytes)
    }

    // -----------------------------------------------------------------------
    // Variable groups  (HIGH VALUE)
    // -----------------------------------------------------------------------

    /// Fetch all pipeline variable groups for a project.
    ///
    /// Each variable group produces a Fragment with all non-secret variable
    /// key=value pairs. Azure DevOps refuses to return secret values (they
    /// arrive as empty strings), so we only emit variables where
    /// `isSecret != true` and the value is non-empty.
    async fn scan_variable_groups(&self, project: &str) -> Vec<Fragment> {
        let url = self.versioned(&format!(
            "{}/{}/{}/_apis/distributedtask/variablegroups",
            self.host, self.organization, project
        ));

        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(source = "azure_devops", project, error = %e, "Failed to list variable groups");
                return Vec::new();
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "azure_devops",
                project,
                status = resp.status().as_u16(),
                "Non-success listing variable groups"
            );
            return Vec::new();
        }

        let groups: AdoList<AdoVariableGroup> = match resp.json().await {
            Ok(g) => g,
            Err(e) => {
                warn!(source = "azure_devops", project, error = %e, "JSON error parsing variable groups");
                return Vec::new();
            }
        };

        let mut fragments = Vec::new();

        for group in &groups.value {
            // Collect all non-secret, non-empty variables.
            let mut lines = Vec::new();
            for (key, var) in &group.variables {
                if var.is_secret {
                    // Azure hides secret values — nothing useful to scan.
                    continue;
                }
                if let Some(val) = &var.value {
                    if !val.is_empty() {
                        lines.push(format!("{key}={val}"));
                    }
                }
            }

            if lines.is_empty() {
                continue;
            }

            // Sort for determinism.
            lines.sort();
            let text = lines.join("\n");
            let content = Bytes::from(text.into_bytes());
            let size = content.len() as u64;

            let mut attributes = HashMap::new();
            attributes.insert("organization".into(), self.organization.clone());
            attributes.insert("project".into(), project.to_owned());
            attributes.insert("variable_group_id".into(), group.id.to_string());
            attributes.insert("variable_group_name".into(), group.name.clone());
            attributes.insert("kind".into(), "variable_group".into());

            debug!(
                source = "azure_devops",
                project,
                group_id = group.id,
                group_name = %group.name,
                variables = lines.len(),
                "Emitting variable group fragment"
            );

            fragments.push(Fragment {
                content,
                metadata: FragmentMetadata {
                    path: format!(
                        "azuredevops://{}/{}/variablegroups/{}",
                        self.organization, project, group.id
                    ),
                    source_type: SourceType::AzureDevOps,
                    size,
                    attributes,
                },
            });
        }

        fragments
    }

    // -----------------------------------------------------------------------
    // Pipeline definitions
    // -----------------------------------------------------------------------

    /// Fetch YAML for each pipeline definition in a project.
    async fn scan_pipelines(&self, project: &str) -> Vec<Fragment> {
        let url = self.versioned(&format!(
            "{}/{}/{}/_apis/pipelines",
            self.host, self.organization, project
        ));

        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(source = "azure_devops", project, error = %e, "Failed to list pipelines");
                return Vec::new();
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "azure_devops",
                project,
                status = resp.status().as_u16(),
                "Non-success listing pipelines"
            );
            return Vec::new();
        }

        let pipelines: AdoList<AdoPipeline> = match resp.json().await {
            Ok(p) => p,
            Err(e) => {
                warn!(source = "azure_devops", project, error = %e, "JSON error parsing pipelines");
                return Vec::new();
            }
        };

        let mut fragments = Vec::new();

        for pipeline in &pipelines.value {
            // Fetch the pipeline YAML definition.
            let yaml_url = self.versioned(&format!(
                "{}/{}/{}/_apis/pipelines/{}/yaml",
                self.host, self.organization, project, pipeline.id
            ));

            let yaml_resp = match self.authed_get(&yaml_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        source = "azure_devops",
                        project,
                        pipeline_id = pipeline.id,
                        error = %e,
                        "Failed to fetch pipeline YAML"
                    );
                    continue;
                }
            };

            if !yaml_resp.status().is_success() {
                // Pipeline YAML endpoint may return 404 for classic pipelines.
                continue;
            }

            // The response is a JSON object with a "finalYaml" field.
            #[derive(Deserialize)]
            struct YamlResponse {
                #[serde(rename = "finalYaml")]
                final_yaml: Option<String>,
            }

            let yaml_body: YamlResponse = match yaml_resp.json().await {
                Ok(y) => y,
                Err(_) => continue,
            };

            let yaml_text = match yaml_body.final_yaml {
                Some(y) if !y.is_empty() => y,
                _ => continue,
            };

            let content = Bytes::from(yaml_text.into_bytes());
            let size = content.len() as u64;
            let mut attributes = HashMap::new();
            attributes.insert("organization".into(), self.organization.clone());
            attributes.insert("project".into(), project.to_owned());
            attributes.insert("pipeline_id".into(), pipeline.id.to_string());
            attributes.insert("pipeline_name".into(), pipeline.name.clone());
            attributes.insert("kind".into(), "pipeline_yaml".into());

            fragments.push(Fragment {
                content,
                metadata: FragmentMetadata {
                    path: format!(
                        "azuredevops://{}/{}/pipelines/{}.yaml",
                        self.organization, project, pipeline.id
                    ),
                    source_type: SourceType::AzureDevOps,
                    size,
                    attributes,
                },
            });
        }

        fragments
    }

    // -----------------------------------------------------------------------
    // Wiki scanning
    // -----------------------------------------------------------------------

    /// Scan all wiki pages for a project.
    async fn scan_wikis(&self, project: &str) -> Vec<Fragment> {
        // First, enumerate wikis in the project.
        #[derive(Deserialize)]
        struct AdoWiki {
            id: String,
            name: String,
        }

        let wikis_url = self.versioned(&format!(
            "{}/{}/{}/_apis/wiki/wikis",
            self.host, self.organization, project
        ));

        let resp = match self.authed_get(&wikis_url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(source = "azure_devops", project, error = %e, "Failed to list wikis");
                return Vec::new();
            }
        };

        if !resp.status().is_success() {
            return Vec::new();
        }

        let wikis: AdoList<AdoWiki> = match resp.json().await {
            Ok(w) => w,
            Err(_) => return Vec::new(),
        };

        let mut fragments = Vec::new();

        for wiki in &wikis.value {
            // Fetch the page tree.
            let pages_url = self.versioned(&format!(
                "{}/{}/{}/_apis/wiki/wikis/{}/pages?recursionLevel=full&includeContent=true",
                self.host, self.organization, project, wiki.id
            ));

            let pages_resp = match self.authed_get(&pages_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        source = "azure_devops",
                        project,
                        wiki_id = %wiki.id,
                        error = %e,
                        "Failed to fetch wiki pages"
                    );
                    continue;
                }
            };

            if !pages_resp.status().is_success() {
                continue;
            }

            // The wiki pages endpoint returns a single root page with sub-pages.
            let root: AdoWikiPage = match pages_resp.json().await {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Flatten and emit pages with content.
            let mut stack = vec![root];
            while let Some(page) = stack.pop() {
                if !page.is_parent {
                    if let Some(ref content_text) = page.content {
                        if !content_text.trim().is_empty() {
                            let content = Bytes::from(content_text.clone().into_bytes());
                            let size = content.len() as u64;
                            let mut attributes = HashMap::new();
                            attributes.insert("organization".into(), self.organization.clone());
                            attributes.insert("project".into(), project.to_owned());
                            attributes.insert("wiki_id".into(), wiki.id.clone());
                            attributes.insert("wiki_name".into(), wiki.name.clone());
                            attributes.insert("kind".into(), "wiki_page".into());

                            fragments.push(Fragment {
                                content,
                                metadata: FragmentMetadata {
                                    path: format!(
                                        "azuredevops://{}/{}/wiki/{}/{}",
                                        self.organization, project, wiki.id, page.path
                                    ),
                                    source_type: SourceType::AzureDevOps,
                                    size,
                                    attributes,
                                },
                            });
                        }
                    }
                }
            }
        }

        fragments
    }

    // -----------------------------------------------------------------------
    // Repository scanning
    // -----------------------------------------------------------------------

    /// Scan all files in a single repository.
    async fn scan_repo(
        &self,
        project: &str,
        repo: &AdoRepo,
    ) -> Vec<Fragment> {
        let branch = repo
            .default_branch
            .as_deref()
            .unwrap_or("main")
            .trim_start_matches("refs/heads/");

        let items = match self.list_items(project, &repo.id, branch).await {
            Ok(i) => i,
            Err(e) => {
                warn!(
                    source = "azure_devops",
                    project,
                    repo = %repo.name,
                    error = %e,
                    "Failed to list items; skipping repo"
                );
                return Vec::new();
            }
        };

        let mut fragments = Vec::new();
        let mut count = 0usize;

        for item in &items {
            if item.is_folder {
                continue;
            }

            // Respect max_depth.
            if self.max_depth > 0 && count >= self.max_depth {
                break;
            }

            // Skip binary files by content-type hint when available.
            if let Some(ref meta) = item.content_metadata {
                if let Some(ref ct) = meta.content_type {
                    if is_likely_binary(ct) {
                        debug!(
                            source = "azure_devops",
                            project,
                            repo = %repo.name,
                            path = %item.path,
                            content_type = %ct,
                            "Skipping likely-binary file"
                        );
                        continue;
                    }
                }
            }

            let blob_id = match &item.object_id {
                Some(id) => id.clone(),
                None => continue,
            };

            let content = match self.fetch_blob(project, &repo.id, &blob_id, &item.path).await {
                Some(c) => c,
                None => continue,
            };

            let size = content.len() as u64;
            let mut attributes = HashMap::new();
            attributes.insert("organization".into(), self.organization.clone());
            attributes.insert("project".into(), project.to_owned());
            attributes.insert("repo_id".into(), repo.id.clone());
            attributes.insert("repo_name".into(), repo.name.clone());
            attributes.insert("blob_id".into(), blob_id.clone());
            attributes.insert("branch".into(), branch.to_owned());

            debug!(
                source = "azure_devops",
                project,
                repo = %repo.name,
                path = %item.path,
                bytes = size,
                "Fetched file"
            );

            fragments.push(Fragment {
                content,
                metadata: FragmentMetadata {
                    path: format!(
                        "azuredevops://{}/{}/{}/{}",
                        self.organization, project, repo.name, item.path.trim_start_matches('/')
                    ),
                    source_type: SourceType::AzureDevOps,
                    size,
                    attributes,
                },
            });

            count += 1;
        }

        fragments
    }

    // -----------------------------------------------------------------------
    // Project-level scan
    // -----------------------------------------------------------------------

    /// Scan a single project: repos, variable groups, pipelines, wikis.
    async fn scan_project(&self, project: &str) -> Vec<Fragment> {
        let mut fragments = Vec::new();

        // Repos.
        let repos = match self.list_repos(project).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    source = "azure_devops",
                    project,
                    error = %e,
                    "Failed to list repos; skipping repo scan"
                );
                Vec::new()
            }
        };

        for repo in &repos {
            debug!(
                source = "azure_devops",
                project,
                repo = %repo.name,
                "Scanning repository"
            );
            let frags = self.scan_repo(project, repo).await;
            fragments.extend(frags);
        }

        // Variable groups.
        if self.scan_variable_groups {
            debug!(source = "azure_devops", project, "Scanning variable groups");
            let frags = self.scan_variable_groups(project).await;
            fragments.extend(frags);
        }

        // Pipelines.
        if self.scan_pipelines {
            debug!(source = "azure_devops", project, "Scanning pipelines");
            let frags = self.scan_pipelines(project).await;
            fragments.extend(frags);
        }

        // Wikis.
        if self.scan_wikis {
            debug!(source = "azure_devops", project, "Scanning wikis");
            let frags = self.scan_wikis(project).await;
            fragments.extend(frags);
        }

        fragments
    }
}

// ============================================================================
// AsyncSource implementation
// ============================================================================

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for AzureDevOpsSource {
    fn name(&self) -> &str {
        "azure_devops"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        let projects: Vec<String> = if let Some(p) = &self.project {
            vec![p.clone()]
        } else {
            self.list_projects()
                .await?
                .into_iter()
                .map(|p| p.name)
                .collect()
        };

        let mut all_fragments = Vec::new();
        for project in &projects {
            debug!(
                source = "azure_devops",
                organization = %self.organization,
                project = %project,
                "Scanning project"
            );
            let frags = self.scan_project(project).await;
            all_fragments.extend(frags);
        }

        Ok(all_fragments)
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Heuristic: return `true` for content types that are almost certainly binary
/// and therefore uninteresting for secret scanning.
fn is_likely_binary(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.starts_with("image/")
        || ct.starts_with("video/")
        || ct.starts_with("audio/")
        || ct.contains("octet-stream")
        || ct.contains("zip")
        || ct.contains("gzip")
        || ct.contains("pdf")
        || ct.contains("font")
        || ct.contains("wasm")
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::traits::AsyncSource;

    #[test]
    fn test_name_returns_azure_devops() {
        let source = AzureDevOpsSource::new("myorg", "my-pat");
        assert_eq!(source.name(), "azure_devops");
    }

    #[test]
    fn test_auth_header_format() {
        let source = AzureDevOpsSource::new("org", "mypattoken");
        let header = source.auth_header();
        assert!(header.starts_with("Basic "), "Should be Basic auth: {header}");
        // Decode and verify format ":PAT"
        let encoded = header.trim_start_matches("Basic ");
        let decoded = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, ":mypattoken");
    }

    #[test]
    fn test_with_project_sets_field() {
        let source = AzureDevOpsSource::new("org", "pat").with_project("my-project");
        assert_eq!(source.project.as_deref(), Some("my-project"));
    }

    #[test]
    fn test_with_variable_groups_sets_flag() {
        let source = AzureDevOpsSource::new("org", "pat").with_variable_groups();
        assert!(source.scan_variable_groups);
    }

    #[test]
    fn test_with_pipelines_sets_flag() {
        let source = AzureDevOpsSource::new("org", "pat").with_pipelines();
        assert!(source.scan_pipelines);
    }

    #[test]
    fn test_with_wikis_sets_flag() {
        let source = AzureDevOpsSource::new("org", "pat").with_wikis();
        assert!(source.scan_wikis);
    }

    #[test]
    fn test_versioned_no_query() {
        let source = AzureDevOpsSource::new("org", "pat");
        let url = source.versioned("https://dev.azure.com/org/_apis/projects");
        assert!(url.contains("api-version=7.1"));
        assert!(url.contains('?'));
    }

    #[test]
    fn test_versioned_with_existing_query() {
        let source = AzureDevOpsSource::new("org", "pat");
        let url = source.versioned("https://dev.azure.com/org/_apis/projects?foo=bar");
        assert!(url.contains("api-version=7.1"));
        assert!(url.contains('&'));
    }

    #[test]
    fn test_is_likely_binary() {
        assert!(is_likely_binary("image/png"));
        assert!(is_likely_binary("application/octet-stream"));
        assert!(is_likely_binary("application/pdf"));
        assert!(!is_likely_binary("text/plain"));
        assert!(!is_likely_binary("application/json"));
        assert!(!is_likely_binary("text/yaml"));
    }

    #[test]
    fn test_env_var_token_fallback() {
        // When passing an empty token, it should fall back to the env var.
        // We don't set the env var in tests so it stays empty — just verify no panic.
        let source = AzureDevOpsSource::new("org", "");
        // token may be empty if env var not set — that's fine.
        let _ = source.auth_header(); // should not panic
    }

    #[test]
    fn test_default_flags() {
        let source = AzureDevOpsSource::new("org", "pat");
        assert!(!source.scan_pipelines);
        assert!(!source.scan_variable_groups);
        assert!(!source.scan_wikis);
        assert_eq!(source.max_depth, 0);
        assert_eq!(source.max_file_size, AzureDevOpsSource::DEFAULT_MAX_FILE_SIZE);
    }

    #[test]
    fn test_branch_strips_refs_prefix() {
        // The branch stripping logic is in scan_repo; test the trim directly.
        let raw = "refs/heads/main";
        let trimmed = raw.trim_start_matches("refs/heads/");
        assert_eq!(trimmed, "main");
    }
}
