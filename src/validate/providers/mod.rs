//! Provider-specific credential validators.
//!
//! Each sub-module implements [`Validator`] for a specific credential provider.
//! The [`all_validators`] function returns the default set used by
//! [`ValidationEngine::new`].
//!
//! [`Validator`]: super::engine::Validator
//! [`ValidationEngine::new`]: super::engine::ValidationEngine::new

pub mod anthropic;
pub mod aws;
pub mod github;
pub mod gitlab;
pub mod huggingface;
pub mod openai;
pub mod slack;
pub mod stripe;

pub use anthropic::AnthropicValidator;
pub use aws::AwsValidator;
pub use github::GithubValidator;
pub use gitlab::GitlabValidator;
pub use huggingface::HuggingFaceValidator;
pub use openai::OpenAiValidator;
pub use slack::SlackValidator;
pub use stripe::StripeValidator;

/// Build the default list of validators sharing a single connection pool.
///
/// The order determines dispatch priority — only the **first** matching
/// validator is invoked. Providers with non-overlapping rule-ID prefixes
/// are order-independent.
pub fn all_validators(client: &reqwest::Client) -> Vec<Box<dyn super::engine::Validator>> {
    vec![
        Box::new(AwsValidator::new(client.clone())),
        Box::new(GithubValidator::new(client.clone())),
        Box::new(GitlabValidator::new(client.clone())),
        Box::new(SlackValidator::new(client.clone())),
        Box::new(StripeValidator::new(client.clone())),
        Box::new(OpenAiValidator::new(client.clone())),
        Box::new(AnthropicValidator::new(client.clone())),
        Box::new(HuggingFaceValidator::new(client.clone())),
    ]
}
