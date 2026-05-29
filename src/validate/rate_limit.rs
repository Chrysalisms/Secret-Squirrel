//! Per-provider token-bucket rate limiter.
//!
//! [`ProviderRateLimiter`] maintains one [`RateLimiter`] per provider string.
//! Limiters are lazily created on the first request for a given provider and
//! cached indefinitely (provider set is small and bounded).
//!
//! # Design
//!
//! Uses `governor` (token bucket algorithm) for accurate rate limiting.
//! The internal `HashMap` is protected by a `Mutex` — contention is minimal
//! because validation is I/O-bound and the lock is held only for the duration
//! of a `HashMap` lookup or insertion, never during the HTTP call itself.

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::{collections::HashMap, num::NonZeroU32, sync::Mutex};

/// Type alias for the concrete limiter type used internally.
type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Stores per-provider token-bucket rate limiters.
///
/// Thread-safe — designed to be shared via `Arc<ProviderRateLimiter>`.
pub struct ProviderRateLimiter {
    /// Map from provider name → its rate limiter.
    limiters: Mutex<HashMap<String, Limiter>>,
    /// Default requests-per-second for providers with no explicit override.
    default_rps: u32,
    /// Per-provider RPS overrides (set before the limiter is first used).
    overrides: Mutex<HashMap<String, u32>>,
}

impl ProviderRateLimiter {
    /// Create a new limiter with the given default RPS cap.
    ///
    /// `default_rps` applies to any provider that hasn't been explicitly
    /// configured via [`set_provider_limit`].
    ///
    /// [`set_provider_limit`]: ProviderRateLimiter::set_provider_limit
    pub fn new(default_rps: u32) -> Self {
        assert!(default_rps > 0, "default_rps must be > 0");
        Self {
            limiters: Mutex::new(HashMap::new()),
            default_rps,
            overrides: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether a request to `provider` is currently permitted.
    ///
    /// Returns `true` if the request is allowed (token consumed), `false` if
    /// the bucket is empty (caller should back off).
    ///
    /// This call is **non-blocking** — it does not wait for a token to become
    /// available.
    pub fn check(&self, provider: &str) -> bool {
        let mut limiters = self.limiters.lock().expect("rate limiter mutex poisoned");

        let limiter = limiters.entry(provider.to_string()).or_insert_with(|| {
            let rps = {
                let overrides = self.overrides.lock().expect("overrides mutex poisoned");
                overrides.get(provider).copied().unwrap_or(self.default_rps)
            };
            build_limiter(rps)
        });

        limiter.check().is_ok()
    }

    /// Override the RPS limit for a specific provider.
    ///
    /// This must be called **before** the first `check` for this provider, or
    /// the cached limiter will not reflect the new limit.
    pub fn set_provider_limit(&self, provider: &str, rps: u32) {
        assert!(rps > 0, "rps must be > 0");
        {
            let mut overrides = self.overrides.lock().expect("overrides mutex poisoned");
            overrides.insert(provider.to_string(), rps);
        }
        // Evict any existing limiter so it is recreated on the next check.
        let mut limiters = self.limiters.lock().expect("rate limiter mutex poisoned");
        limiters.remove(provider);
    }
}

/// Build a `RateLimiter` allowing `rps` requests per second.
fn build_limiter(rps: u32) -> Limiter {
    let quota = Quota::per_second(NonZeroU32::new(rps).expect("rps must be nonzero"));
    RateLimiter::direct(quota)
}

// ===========================
// Tests
// ===========================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_request_always_allowed() {
        let limiter = ProviderRateLimiter::new(10);
        assert!(
            limiter.check("github"),
            "First request should always be allowed"
        );
    }

    #[test]
    fn test_rate_limiter_blocks_after_burst() {
        // Create a limiter with 1 RPS.
        let limiter = ProviderRateLimiter::new(1);
        // Governor's token bucket starts full (1 token).
        let first = limiter.check("stripe");
        assert!(first, "First request should be allowed");
        // Immediately after consuming the only token, the next should be blocked.
        let second = limiter.check("stripe");
        assert!(!second, "Second immediate request should be rate-limited");
    }

    #[test]
    fn test_separate_providers_are_independent() {
        let limiter = ProviderRateLimiter::new(1);
        assert!(limiter.check("github"));
        // github is now blocked, but openai should be independent
        let _ = limiter.check("github"); // exhaust github
        assert!(limiter.check("openai"), "openai should have its own bucket");
    }

    #[test]
    fn test_set_provider_limit_overrides_default() {
        let limiter = ProviderRateLimiter::new(10);
        // Set a 1 RPS limit for aws before any check
        limiter.set_provider_limit("aws", 1);
        assert!(limiter.check("aws"));
        // Should now be blocked
        assert!(!limiter.check("aws"), "aws should be rate-limited at 1 RPS");
    }

    #[test]
    fn test_multiple_providers_coexist() {
        let limiter = ProviderRateLimiter::new(5);
        for _ in 0..5 {
            let _ = limiter.check("github");
        }
        // openai should have its own full bucket regardless
        assert!(limiter.check("openai"));
    }
}
