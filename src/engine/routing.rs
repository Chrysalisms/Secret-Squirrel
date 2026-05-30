use crate::rules::CompiledRule;
use crate::types::{CandidateFeatures, CandidateRoute, DiscoveryCandidate, MatchKind, ProximityPattern, RoutedCandidate};

#[derive(Debug, Clone, Default)]
pub struct RuleBucketIndexes {
    pub api_key: Vec<usize>,
    pub password: Vec<usize>,
    pub token: Vec<usize>,
    pub url_credentials: Vec<usize>,
    pub private_key: Vec<usize>,
    pub nonce_like: Vec<usize>,
    pub auth_header: Vec<usize>,
    pub code_assignments: Vec<usize>,
    pub config_assignments: Vec<usize>,
    pub keywordless: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct CandidateRoutingStats {
    pub routed_candidates: usize,
    pub dropped_low_signal: usize,
    pub dropped_no_bucket: usize,
}

impl RuleBucketIndexes {
    pub fn build(rules: &[CompiledRule]) -> Self {
        let mut indexes = Self::default();
        for (idx, rule) in rules.iter().enumerate() {
            let id = rule.id.to_lowercase();
            let keyword_blob = rule
                .keywords
                .iter()
                .map(|k| k.to_lowercase())
                .collect::<Vec<_>>()
                .join(" ");
            if rule.keywords.is_empty() {
                indexes.keywordless.push(idx);
            }
            if id.contains("api-key")
                || id.contains("secret-key")
                || id.contains("access-key")
                || id.contains("client-secret")
                || id.contains("client-id")
                || id.contains("oauth")
                || id.contains("webhook")
                || id.contains("hmac")
                || id.contains("signing-key")
                || id.contains("session-secret")
                || keyword_blob.contains("x-api-key")
                || keyword_blob.contains("api-key")
                || keyword_blob.contains("access key")
            {
                indexes.api_key.push(idx);
            }
            if id.contains("password")
                || id.contains("smtp")
                || keyword_blob.contains("password")
                || keyword_blob.contains("passwd")
            {
                indexes.password.push(idx);
            }
            if id.contains("token")
                || id.contains("secret")
                || id.contains("oauth")
                || id.contains("jwt")
                || id.contains("bearer")
                || id.contains("session-secret")
                || id.contains("webhook")
                || id.contains("hmac")
                || keyword_blob.contains("token")
                || keyword_blob.contains("secret")
            {
                indexes.token.push(idx);
            }
            if id.contains("bearer")
                || id.contains("jwt")
                || id.contains("auth")
                || keyword_blob.contains("bearer")
                || keyword_blob.contains("authorization")
                || keyword_blob.contains("cookie")
            {
                indexes.auth_header.push(idx);
            }
            if id.contains("header") || id.contains("cookie") || id.contains("session") {
                indexes.auth_header.push(idx);
            }
            if id.contains("generic")
                || id.contains("assignment")
                || id.contains("password")
                || id.contains("token")
            {
                indexes.code_assignments.push(idx);
                indexes.config_assignments.push(idx);
            }
            if id.contains("api-key")
                || id.contains("secret")
                || id.contains("oauth")
                || id.contains("client")
                || id.contains("access-key")
            {
                indexes.code_assignments.push(idx);
            }
            if id.contains("env")
                || id.contains("config")
                || id.contains("url")
                || id.contains("credential")
            {
                indexes.config_assignments.push(idx);
            }
            if id.contains("url") || id.contains("database-url") || id.contains("credentials") {
                indexes.url_credentials.push(idx);
            }
            if id.contains("private-key") || id.contains("pem") || id.contains("signing-key") {
                indexes.private_key.push(idx);
            }
            if id.contains("nonce") {
                indexes.nonce_like.push(idx);
            }
        }
        indexes
    }

    pub fn keywordless(&self) -> &[usize] {
        &self.keywordless
    }

    pub fn for_candidate<'a>(&'a self, candidate: &RoutedCandidate, path: &str) -> &'a [usize] {
        let evidence = &candidate.candidate.evidence;
        if matches!(
            evidence.proximity_pattern,
            ProximityPattern::Assignment | ProximityPattern::FunctionArg
        ) && !evidence.multiline
            && evidence.has_secret_identifier
        {
            return &self.code_assignments;
        }
        if matches!(evidence.proximity_pattern, ProximityPattern::HeaderValue) {
            return match evidence.kind {
                MatchKind::ApiKeyAssignment => &self.api_key,
                MatchKind::BearerAuth | MatchKind::Jwt | MatchKind::TokenAssignment => {
                    if self.auth_header.is_empty() {
                        &self.token
                    } else {
                        &self.auth_header
                    }
                }
                _ => &self.code_assignments,
            };
        }
        if matches!(
            evidence.proximity_pattern,
            ProximityPattern::JsonKey
                | ProximityPattern::YamlKey
                | ProximityPattern::Export
                | ProximityPattern::DockerEnv
                | ProximityPattern::EnvVar
                | ProximityPattern::TerraformVar
        ) {
            return &self.config_assignments;
        }
        if is_config_like_path(path) {
            return &self.config_assignments;
        }
        match candidate.route {
            CandidateRoute::ApiKey => &self.api_key,
            CandidateRoute::Password => &self.password,
            CandidateRoute::Token => &self.token,
            CandidateRoute::AuthHeader => {
                if self.auth_header.is_empty() {
                    &self.token
                } else {
                    &self.auth_header
                }
            }
            CandidateRoute::UrlCredential => &self.url_credentials,
            CandidateRoute::PrivateKey => &self.private_key,
            CandidateRoute::Generic | CandidateRoute::Config => &self.code_assignments,
        }
    }
}

pub fn route_candidates(
    candidates: Vec<DiscoveryCandidate>,
    path: &str,
    entropy_threshold: f32,
    buckets: &RuleBucketIndexes,
) -> (Vec<RoutedCandidate>, CandidateRoutingStats) {
    let mut out = Vec::new();
    let mut stats = CandidateRoutingStats::default();
    for candidate in candidates {
        let features = extract_features(&candidate, path);
        if features.entropy < entropy_threshold * 0.75
            && !features.typed
            && !features.has_secret_identifier
            && !features.has_auth_context
            && !features.multiline
            && features.path_score < 0.55
        {
            stats.dropped_low_signal += 1;
            continue;
        }

        let route = choose_route(&candidate, &features, path);
        let routed = RoutedCandidate {
            candidate,
            features,
            route,
        };

        if buckets.for_candidate(&routed, path).is_empty() {
            stats.dropped_no_bucket += 1;
            continue;
        }

        stats.routed_candidates += 1;
        out.push(routed);
    }
    (out, stats)
}

fn extract_features(candidate: &DiscoveryCandidate, path: &str) -> CandidateFeatures {
    CandidateFeatures {
        entropy: candidate.entropy_score,
        proximity: candidate.proximity_score,
        structure: candidate.structure_score,
        typed: candidate.evidence.typed,
        multiline: candidate.evidence.multiline,
        has_secret_identifier: candidate.evidence.has_secret_identifier,
        has_auth_context: candidate.evidence.has_auth_context,
        path_score: path_score(path),
    }
}

fn choose_route(
    candidate: &DiscoveryCandidate,
    features: &CandidateFeatures,
    path: &str,
) -> CandidateRoute {
    match candidate.evidence.kind {
        MatchKind::ApiKeyAssignment => CandidateRoute::ApiKey,
        MatchKind::PasswordAssignment => CandidateRoute::Password,
        MatchKind::TokenAssignment => CandidateRoute::Token,
        MatchKind::BearerAuth | MatchKind::Jwt => CandidateRoute::AuthHeader,
        MatchKind::UrlCredentials => CandidateRoute::UrlCredential,
        MatchKind::PrivateKey => CandidateRoute::PrivateKey,
        MatchKind::NonceLike => CandidateRoute::Token,
        MatchKind::Catchall | MatchKind::Unknown => {
            if candidate.evidence.has_auth_context
                || matches!(candidate.evidence.proximity_pattern, ProximityPattern::HeaderValue)
            {
                CandidateRoute::AuthHeader
            } else if is_config_like_path(path) || features.path_score > 0.7 {
                CandidateRoute::Config
            } else {
                CandidateRoute::Generic
            }
        }
    }
}

fn path_score(path: &str) -> f32 {
    let lower = path.to_lowercase();
    let mut score: f32 = 0.0;
    if is_config_like_path(path) {
        score += 0.45;
    }
    if lower.contains("/test/")
        || lower.contains("\\test\\")
        || lower.contains("/tests/")
        || lower.contains("\\tests\\")
        || lower.contains("/fixture")
        || lower.contains("\\fixture")
        || lower.contains("/example")
        || lower.contains("\\example")
    {
        score += 0.25;
    }
    if lower.contains("/src/") || lower.contains("\\src\\") {
        score += 0.15;
    }
    score.min(1.0)
}

pub fn is_config_like_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".env")
        || lower.ends_with(".env.example")
        || lower.ends_with(".env.sample")
        || lower.ends_with(".env.local")
        || lower.ends_with(".json")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".toml")
        || lower.ends_with(".ini")
        || lower.ends_with(".conf")
        || lower.ends_with(".config")
        || lower.ends_with(".properties")
        || lower.ends_with(".tfvars")
        || lower.ends_with(".example")
        || lower.contains("/config")
        || lower.contains("\\config")
        || lower.contains("/conf/")
        || lower.contains("\\conf\\")
        || lower.contains("settings")
}
