//! Git history source — walks commits and diffs to produce one [`Fragment`]
//! per changed file per commit.
//!
//! Uses the [`git2`] crate (libgit2 bindings) to open a repository, walk
//! its commit history via `revwalk`, and diff each commit against its first
//! parent to extract only the *changed* content for scanning.
//!
//! # Depth Limiting
//!
//! If `depth > 0`, the walk stops after that many commits. Set `depth = 0`
//! to walk the full history (may be slow on large repos).

use crate::error::{Result, SquirrelError};
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};
use bytes::Bytes;
use git2::{DiffFormat, DiffOptions, Repository};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, warn};

/// A source that produces one [`Fragment`] per changed file per commit in a
/// Git repository's history.
pub struct GitSource {
    repo: Repository,
    /// Maximum number of commits to walk (0 = unlimited).
    depth: usize,
}

impl GitSource {
    /// Open a Git repository at `repo_path` and prepare to walk its history.
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Git`] if `repo_path` is not a valid git
    /// repository or cannot be opened.
    pub fn new(repo_path: PathBuf, depth: usize) -> Result<Self> {
        let repo = Repository::open(&repo_path)?;
        Ok(Self { repo, depth })
    }

    /// Format a Unix timestamp as an ISO-8601 date string (UTC).
    fn format_time(time: git2::Time) -> String {
        use chrono::{TimeZone, Utc};
        let dt = Utc
            .timestamp_opt(time.seconds(), 0)
            .single()
            .unwrap_or_else(Utc::now);
        dt.to_rfc3339()
    }
}

impl SyncSource for GitSource {
    fn name(&self) -> &str {
        "git"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        // Build the revwalk starting from HEAD.
        let mut revwalk = match self.repo.revwalk() {
            Ok(rw) => rw,
            Err(e) => {
                return Box::new(std::iter::once(Err(SquirrelError::Git(e))));
            }
        };

        if let Err(e) = revwalk.push_head() {
            return Box::new(std::iter::once(Err(SquirrelError::Git(e))));
        }

        // Sort chronologically (newest first is the default — that's fine).
        let depth = self.depth;
        let repo = &self.repo;

        // Collect commit OIDs up to the depth limit.
        let oids: Vec<_> = revwalk
            .take(if depth == 0 { usize::MAX } else { depth })
            .filter_map(|oid_result| match oid_result {
                Ok(oid) => Some(oid),
                Err(e) => {
                    warn!("revwalk error: {e}");
                    None
                }
            })
            .collect();

        // For each commit OID, diff against its first parent and produce
        // one Fragment per changed file.
        let fragments: Vec<Result<Fragment>> = oids
            .into_iter()
            .flat_map(|oid| {
                let commit = match repo.find_commit(oid) {
                    Ok(c) => c,
                    Err(e) => return vec![Err(SquirrelError::Git(e))],
                };

                let commit_hash = commit.id().to_string();
                let author = commit.author().name().unwrap_or("unknown").to_string();
                let date = Self::format_time(commit.author().when());
                let message = commit
                    .message()
                    .unwrap_or("")
                    .chars()
                    .take(72)
                    .collect::<String>();

                // Get the tree for this commit.
                let tree = match commit.tree() {
                    Ok(t) => t,
                    Err(e) => return vec![Err(SquirrelError::Git(e))],
                };

                // Get parent tree (if any — root commits have no parent).
                let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());

                let mut diff_opts = DiffOptions::new();
                diff_opts.include_untracked(false);

                let diff = match repo.diff_tree_to_tree(
                    parent_tree.as_ref(),
                    Some(&tree),
                    Some(&mut diff_opts),
                ) {
                    Ok(d) => d,
                    Err(e) => return vec![Err(SquirrelError::Git(e))],
                };

                // Collect diff hunks per file path.
                let mut file_contents: HashMap<String, Vec<u8>> = HashMap::new();

                // Collect added/context lines per file path.
                let _ = diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
                    use git2::DiffLineType::*;
                    // Only capture added lines (new content in this commit).
                    if matches!(line.origin_value(), Addition | Context) {
                        let path = _delta
                            .new_file()
                            .path()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "<unknown>".to_string());
                        file_contents
                            .entry(path)
                            .or_default()
                            .extend_from_slice(line.content());
                    }
                    true
                });

                debug!(
                    "git: commit {} touched {} files",
                    &commit_hash[..8],
                    file_contents.len()
                );

                file_contents
                    .into_iter()
                    .map(|(file_path, raw)| {
                        let size = raw.len() as u64;
                        let mut attrs = HashMap::new();
                        attrs.insert("commit_hash".to_string(), commit_hash.clone());
                        attrs.insert("author".to_string(), author.clone());
                        attrs.insert("date".to_string(), date.clone());
                        attrs.insert("message".to_string(), message.clone());

                        // Construct a virtual path: "<file>@<short-hash>"
                        let virtual_path =
                            format!("{}@{}", file_path, &commit_hash[..8]);

                        Ok(Fragment {
                            content: Bytes::from(raw),
                            metadata: FragmentMetadata {
                                path: virtual_path,
                                source_type: SourceType::Git,
                                size,
                                attributes: attrs,
                            },
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        Box::new(fragments.into_iter())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Repository, Signature};
    use std::fs;
    use tempfile::TempDir;

    /// Initialize a temp git repo with one commit containing a test secret.
    ///
    /// Does NOT return `Repository` — git2 `Tree`/`Commit` borrow from
    /// `Repository` via lifetime, making it impossible to move `repo` after
    /// calling `find_tree`. Open a fresh handle via `Repository::open` instead.
    fn make_repo_with_commit(dir: &TempDir) {
        let repo = Repository::init(dir.path()).unwrap();
        {
            let mut config = repo.config().unwrap();
            config.set_str("user.name", "Test User").unwrap();
            config.set_str("user.email", "test@example.com").unwrap();
        }
        let secret_file = dir.path().join("secrets.env");
        fs::write(
            &secret_file,
            b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        )
        .unwrap();
        {
            let mut index = repo.index().unwrap();
            index.add_path(std::path::Path::new("secrets.env")).unwrap();
            index.write().unwrap();
            let tree_oid = index.write_tree().unwrap();
            let tree = repo.find_tree(tree_oid).unwrap();
            let sig = Signature::now("Test User", "test@example.com").unwrap();
            repo.commit(Some("HEAD"), &sig, &sig, "Add secrets file", &tree, &[])
                .unwrap();
        }
    }

    #[test]
    fn test_fragment_contains_secret_content() {
        let dir = TempDir::new().unwrap();
        make_repo_with_commit(&dir);

        let source = GitSource::new(dir.path().to_path_buf(), 0).unwrap();
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert!(!fragments.is_empty(), "expected at least one fragment from git history");

        let has_secret = fragments.iter().any(|f| {
            let content = std::str::from_utf8(&f.content).unwrap_or("");
            content.contains("wJalrXUtnFEMI")
        });
        assert!(has_secret, "fragment content should contain the AWS secret");
    }

    #[test]
    fn test_fragment_has_git_attributes() {
        let dir = TempDir::new().unwrap();
        make_repo_with_commit(&dir);

        let source = GitSource::new(dir.path().to_path_buf(), 0).unwrap();
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert!(!fragments.is_empty());
        let f = &fragments[0];
        assert_eq!(f.metadata.source_type, SourceType::Git);
        assert!(f.metadata.attributes.contains_key("commit_hash"));
        assert!(f.metadata.attributes.contains_key("author"));
        assert!(f.metadata.attributes.contains_key("date"));
    }

    #[test]
    fn test_depth_limit_respected() {
        let dir = TempDir::new().unwrap();
        make_repo_with_commit(&dir);

        // Add a second commit by opening the repo fresh.
        {
            let repo = Repository::open(dir.path()).unwrap();
            let second_file = dir.path().join("second.txt");
            fs::write(&second_file, b"another_secret=hunter2\n").unwrap();
            let mut index = repo.index().unwrap();
            index.add_path(std::path::Path::new("second.txt")).unwrap();
            index.write().unwrap();
            let tree_oid = index.write_tree().unwrap();
            let tree = repo.find_tree(tree_oid).unwrap();
            let sig = Signature::now("Test User", "test@example.com").unwrap();
            let head = repo.head().unwrap().peel_to_commit().unwrap();
            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                "Second commit",
                &tree,
                &[&head],
            )
            .unwrap();
        }

        // With depth=1 only the latest commit should be walked.
        let source = GitSource::new(dir.path().to_path_buf(), 1).unwrap();
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();
        let has_second = fragments
            .iter()
            .any(|f| f.metadata.path.contains("second.txt"));
        assert!(has_second, "depth=1 should include the latest commit's file");
    }

    #[test]
    fn test_invalid_repo_returns_error() {
        let dir = TempDir::new().unwrap();
        // Not a git repo — should return an error.
        let result = GitSource::new(dir.path().to_path_buf(), 0);
        assert!(result.is_err());
    }
}
