//! Remediation guidance — provider-specific secret rotation guides.
//!
//! Each [`RemediationGuide`] provides:
//! - A direct link to the provider's credential rotation page
//! - Step-by-step rotation instructions
//! - A suggestion for storing the new credential securely in a vault
//!
//! Guides are static data embedded in the binary — no network call required.

// ============================================================================
// RemediationGuide
// ============================================================================

/// Provider-specific credential rotation guide.
#[derive(Debug, Clone)]
pub struct RemediationGuide {
    /// The name of the provider (e.g., `"AWS"`, `"GitHub"`).
    pub provider: &'static str,
    /// URL to the provider's credential rotation or revocation page.
    pub rotation_url: &'static str,
    /// Ordered list of rotation steps (static slice — const-constructible).
    pub steps: &'static [&'static str],
    /// Suggestion for securely storing the replacement credential.
    pub vault_suggestion: &'static str,
}

// ============================================================================
// Static guide data
// ============================================================================

static GUIDE_AWS: RemediationGuide = RemediationGuide {
    provider: "AWS",
    rotation_url: "https://console.aws.amazon.com/iam/home#/security_credentials",
    steps: &[
        "1. Go to IAM → Security credentials → Access keys.",
        "2. Click 'Deactivate' on the exposed key immediately.",
        "3. Check CloudTrail logs for unauthorized usage since the key was exposed.",
        "4. Generate a new access key and update all services/CI pipelines.",
        "5. Delete the old (deactivated) key once all references are updated.",
        "6. Enable AWS Secrets Manager or Parameter Store for future key storage.",
    ],
    vault_suggestion: "Store your new AWS credentials in AWS Secrets Manager, HashiCorp Vault, or \
         your CI/CD platform's native secrets store (e.g. GitHub Actions Secrets).",
};

static GUIDE_GITHUB: RemediationGuide = RemediationGuide {
    provider: "GitHub",
    rotation_url: "https://github.com/settings/tokens",
    steps: &[
        "1. Go to GitHub → Settings → Developer settings → Personal access tokens.",
        "2. Click 'Delete' or 'Revoke' on the exposed token immediately.",
        "3. Audit recent API calls using the GitHub audit log (requires org plan).",
        "4. Generate a new token with only the minimum required scopes.",
        "5. Replace the old token in all services, CI/CD pipelines, and dotfiles.",
        "6. Consider switching to GitHub App installation tokens for reduced scope.",
    ],
    vault_suggestion: "Store the new token in your CI/CD platform's secrets store or a password \
         manager. Never commit it to any repository.",
};

static GUIDE_GITLAB: RemediationGuide = RemediationGuide {
    provider: "GitLab",
    rotation_url: "https://gitlab.com/-/user_settings/personal_access_tokens",
    steps: &[
        "1. Go to GitLab → User Settings → Access Tokens.",
        "2. Click 'Revoke' on the exposed token immediately.",
        "3. Review GitLab audit events for unauthorized usage.",
        "4. Create a new token with only the minimum required scopes.",
        "5. Update all services and CI/CD pipelines with the new token.",
    ],
    vault_suggestion: "Use GitLab CI/CD variables (masked + protected) or an external vault \
         (HashiCorp Vault, AWS Secrets Manager) to store the replacement token.",
};

static GUIDE_SLACK: RemediationGuide = RemediationGuide {
    provider: "Slack",
    rotation_url: "https://api.slack.com/apps",
    steps: &[
        "1. Go to api.slack.com/apps → select your app → OAuth & Permissions.",
        "2. Click 'Revoke All OAuth Tokens' to immediately invalidate the token.",
        "3. Review your Slack audit logs for unauthorized message reads or posts.",
        "4. Regenerate the bot/user token and update all integrations.",
        "5. Rotate your app's signing secret as well if it may have been exposed.",
    ],
    vault_suggestion: "Store Slack tokens in your CI/CD platform's secrets or a dedicated \
         secrets manager. Set up Slack's token rotation webhook for automatic rotation.",
};

static GUIDE_STRIPE: RemediationGuide = RemediationGuide {
    provider: "Stripe",
    rotation_url: "https://dashboard.stripe.com/apikeys",
    steps: &[
        "1. Go to Stripe Dashboard → Developers → API Keys.",
        "2. Click 'Roll key...' on the exposed key — Stripe supports zero-downtime rotation.",
        "3. Check the Stripe Dashboard logs for unauthorized charges or data access.",
        "4. Update all backend services and CI/CD pipelines with the new key.",
        "5. Set up Stripe's Radar rules and review rate limits for suspicious activity.",
    ],
    vault_suggestion:
        "Use Stripe's built-in restricted keys with the minimum required permissions. \
         Store in AWS Secrets Manager, HashiCorp Vault, or your cloud provider's \
         native secrets service.",
};

static GUIDE_OPENAI: RemediationGuide = RemediationGuide {
    provider: "OpenAI",
    rotation_url: "https://platform.openai.com/api-keys",
    steps: &[
        "1. Go to platform.openai.com → API Keys.",
        "2. Click the delete (trash) icon on the exposed key immediately.",
        "3. Check your OpenAI usage dashboard for unexpected API calls.",
        "4. Create a new API key and update all services and CI pipelines.",
        "5. Set usage limits and alerts on the new key to detect future abuse.",
    ],
    vault_suggestion: "Store OpenAI API keys in your CI/CD platform's native secrets store or \
         a dedicated secrets manager. Never hardcode keys in source files.",
};

static GUIDE_ANTHROPIC: RemediationGuide = RemediationGuide {
    provider: "Anthropic",
    rotation_url: "https://console.anthropic.com/settings/keys",
    steps: &[
        "1. Go to console.anthropic.com → Settings → API Keys.",
        "2. Delete the exposed key immediately.",
        "3. Review your Anthropic usage logs for unauthorized API calls.",
        "4. Create a new key and update all services.",
        "5. Implement request logging to detect abuse early.",
    ],
    vault_suggestion: "Store Anthropic API keys in a secrets manager such as AWS Secrets Manager, \
         HashiCorp Vault, or your CI/CD platform's native secrets store.",
};

static GUIDE_HUGGINGFACE: RemediationGuide = RemediationGuide {
    provider: "HuggingFace",
    rotation_url: "https://huggingface.co/settings/tokens",
    steps: &[
        "1. Go to huggingface.co → Settings → Access Tokens.",
        "2. Delete the exposed token immediately.",
        "3. Check your HuggingFace account activity for unauthorized downloads or uploads.",
        "4. Create a new token with only the minimum required permissions (read vs. write).",
        "5. Update all services and scripts with the new token.",
    ],
    vault_suggestion: "Store HuggingFace tokens in your CI/CD secrets store. \
         Use read-only tokens for inference and write tokens only in secure pipelines.",
};

// ============================================================================
// Lookup function
// ============================================================================

/// Get a remediation guide for a rule ID or category keyword.
///
/// Matches by rule ID prefix or well-known provider name. Returns `None` if
/// no specific guide is available.
pub fn get_remediation(rule_id: &str) -> Option<&'static RemediationGuide> {
    // Match by rule ID prefix.
    if rule_id.starts_with("aws-") {
        return Some(&GUIDE_AWS);
    }
    if rule_id.starts_with("github-") {
        return Some(&GUIDE_GITHUB);
    }
    if rule_id.starts_with("gitlab-") {
        return Some(&GUIDE_GITLAB);
    }
    if rule_id.starts_with("slack-") {
        return Some(&GUIDE_SLACK);
    }
    if rule_id.starts_with("stripe-") {
        return Some(&GUIDE_STRIPE);
    }
    if rule_id.starts_with("openai-") {
        return Some(&GUIDE_OPENAI);
    }
    if rule_id.starts_with("anthropic-") {
        return Some(&GUIDE_ANTHROPIC);
    }
    if rule_id.starts_with("huggingface-") || rule_id.starts_with("hugging-face-") {
        return Some(&GUIDE_HUGGINGFACE);
    }

    // Exact matches for well-known rule IDs.
    match rule_id {
        "private-key-rsa" | "private-key-ec" | "private-key-generic" => {
            // For private keys, no single provider — give generic advice.
            None
        }
        _ => None,
    }
}

/// Returns a plain-text remediation string for a given rule ID.
///
/// This is a convenience wrapper used by the finding formatter.
pub fn guidance_for_rule(rule_id: &str) -> Option<&'static str> {
    get_remediation(rule_id).map(|g| g.vault_suggestion)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_guide_found() {
        let guide = get_remediation("aws-access-key-id");
        assert!(guide.is_some());
        assert_eq!(guide.unwrap().provider, "AWS");
    }

    #[test]
    fn test_github_guide_found() {
        let guide = get_remediation("github-pat");
        assert!(guide.is_some());
        assert_eq!(guide.unwrap().provider, "GitHub");
    }

    #[test]
    fn test_gitlab_guide_found() {
        let guide = get_remediation("gitlab-pat");
        assert!(guide.is_some());
        assert_eq!(guide.unwrap().provider, "GitLab");
    }

    #[test]
    fn test_slack_guide_found() {
        let guide = get_remediation("slack-token");
        assert!(guide.is_some());
        assert_eq!(guide.unwrap().provider, "Slack");
    }

    #[test]
    fn test_stripe_guide_found() {
        let guide = get_remediation("stripe-live-key");
        assert!(guide.is_some());
        assert_eq!(guide.unwrap().provider, "Stripe");
    }

    #[test]
    fn test_openai_guide_found() {
        let guide = get_remediation("openai-api-key");
        assert!(guide.is_some());
        assert_eq!(guide.unwrap().provider, "OpenAI");
    }

    #[test]
    fn test_anthropic_guide_found() {
        let guide = get_remediation("anthropic-api-key");
        assert!(guide.is_some());
        assert_eq!(guide.unwrap().provider, "Anthropic");
    }

    #[test]
    fn test_huggingface_guide_found() {
        let guide = get_remediation("huggingface-token");
        assert!(guide.is_some());
        assert_eq!(guide.unwrap().provider, "HuggingFace");
    }

    #[test]
    fn test_unknown_rule_returns_none() {
        assert!(get_remediation("unknown-obscure-provider-xyz").is_none());
    }

    #[test]
    fn test_guide_has_rotation_url() {
        let guide = get_remediation("aws-secret-key").unwrap();
        assert!(!guide.rotation_url.is_empty());
        assert!(guide.rotation_url.starts_with("https://"));
    }

    #[test]
    fn test_guide_has_steps() {
        let guide = get_remediation("github-oauth").unwrap();
        assert!(!guide.steps.is_empty(), "guide must have at least one step");
    }

    #[test]
    fn test_guidance_for_rule_convenience() {
        let text = guidance_for_rule("aws-access-key-id");
        assert!(text.is_some());
        assert!(!text.unwrap().is_empty());
    }
}
