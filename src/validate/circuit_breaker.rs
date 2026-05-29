//! Circuit breaker pattern for provider validation endpoints.
//!
//! Prevents cascading failures when a provider API is down or rate-limiting
//! aggressively. Each provider transitions through three states:
//!
//! ```text
//! Closed ──(N failures)──→ Open ──(cooldown elapsed)──→ HalfOpen
//!   ↑                                                       │
//!   └────────────────────(success)──────────────────────────┘
//! ```
//!
//! - **Closed**: Normal operation. All requests pass through.
//! - **Open**: Provider is considered down. All requests are rejected
//!   immediately (no network call) until the cooldown expires.
//! - **HalfOpen**: One probe request is allowed through. A success closes
//!   the breaker; a failure resets the cooldown and returns to Open.
//!
//! # Thread safety
//!
//! [`CircuitBreaker`] uses a `Mutex<HashMap<String, CircuitEntry>>` internally
//! and is designed to be shared via `Arc<CircuitBreaker>`.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// The state of a circuit for a single provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — requests are allowed through.
    Closed,
    /// Too many consecutive failures — requests are rejected without a network
    /// call. The circuit will transition to `HalfOpen` after the cooldown.
    Open,
    /// The cooldown has elapsed — one probe request is allowed. A success
    /// returns to `Closed`; a failure resets the timer and returns to `Open`.
    HalfOpen,
}

/// Internal per-provider state record.
struct CircuitEntry {
    state: CircuitState,
    /// Number of consecutive failures since last success (or creation).
    failures: u32,
    /// Timestamp of the most recent failure (used for cooldown calculation).
    last_failure: Option<Instant>,
}

impl CircuitEntry {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            failures: 0,
            last_failure: None,
        }
    }
}

/// A per-provider circuit breaker.
///
/// Wraps an internal `HashMap` protected by a `Mutex`. The lock is held only
/// for the brief duration of state reads/writes — never across network I/O.
pub struct CircuitBreaker {
    states: Mutex<HashMap<String, CircuitEntry>>,
    /// Number of consecutive failures before the circuit opens.
    failure_threshold: u32,
    /// How long to wait in the Open state before probing again.
    cooldown: Duration,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// # Arguments
    ///
    /// * `failure_threshold` — consecutive failures before opening (default: 5)
    /// * `cooldown_secs` — seconds to remain open before probing (default: 60)
    pub fn new(failure_threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            failure_threshold,
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// Returns `true` if a request to `provider` should be allowed.
    ///
    /// Transitions `Open → HalfOpen` automatically when the cooldown expires.
    /// Never transitions `Closed → Open` (that is [`record_failure`]'s job).
    ///
    /// [`record_failure`]: CircuitBreaker::record_failure
    pub fn allow(&self, provider: &str) -> bool {
        let mut states = self.states.lock().expect("circuit breaker mutex poisoned");
        let entry = states
            .entry(provider.to_string())
            .or_insert_with(CircuitEntry::new);

        match entry.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                // Check whether the cooldown has elapsed
                if let Some(last) = entry.last_failure {
                    if last.elapsed() >= self.cooldown {
                        entry.state = CircuitState::HalfOpen;
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Record a successful request to `provider`.
    ///
    /// Resets the failure counter and closes the circuit (regardless of current
    /// state — a success in HalfOpen closes it, a success in Closed keeps it
    /// closed).
    pub fn record_success(&self, provider: &str) {
        let mut states = self.states.lock().expect("circuit breaker mutex poisoned");
        let entry = states
            .entry(provider.to_string())
            .or_insert_with(CircuitEntry::new);
        entry.failures = 0;
        entry.state = CircuitState::Closed;
        entry.last_failure = None;
    }

    /// Record a failed request to `provider`.
    ///
    /// Increments the failure counter. If the counter reaches
    /// `failure_threshold` (or the circuit was already `HalfOpen`), the
    /// circuit transitions to `Open`.
    pub fn record_failure(&self, provider: &str) {
        let mut states = self.states.lock().expect("circuit breaker mutex poisoned");
        let entry = states
            .entry(provider.to_string())
            .or_insert_with(CircuitEntry::new);

        entry.failures += 1;
        entry.last_failure = Some(Instant::now());

        if entry.failures >= self.failure_threshold || entry.state == CircuitState::HalfOpen {
            entry.state = CircuitState::Open;
        }
    }

    /// Return a snapshot of the current circuit state for `provider`.
    ///
    /// Note: the state may change immediately after this call returns. Use
    /// [`allow`] for gating — it has the side-effect of transitioning
    /// `Open → HalfOpen` when appropriate.
    ///
    /// [`allow`]: CircuitBreaker::allow
    pub fn state(&self, provider: &str) -> CircuitState {
        let mut states = self.states.lock().expect("circuit breaker mutex poisoned");
        states
            .entry(provider.to_string())
            .or_insert_with(CircuitEntry::new)
            .state
            .clone()
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, 60)
    }
}

// ===========================
// Tests
// ===========================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_is_closed() {
        let cb = CircuitBreaker::new(5, 60);
        assert_eq!(cb.state("github"), CircuitState::Closed);
        assert!(cb.allow("github"));
    }

    #[test]
    fn test_opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(3, 60);
        for _ in 0..2 {
            cb.record_failure("stripe");
            // Not yet open
            assert_eq!(cb.state("stripe"), CircuitState::Closed);
        }
        cb.record_failure("stripe");
        assert_eq!(cb.state("stripe"), CircuitState::Open);
        assert!(
            !cb.allow("stripe"),
            "Circuit should be open and reject requests"
        );
    }

    #[test]
    fn test_success_resets_failure_counter() {
        let cb = CircuitBreaker::new(3, 60);
        cb.record_failure("aws");
        cb.record_failure("aws");
        cb.record_success("aws");
        // Counter reset — two more failures should not open it immediately
        cb.record_failure("aws");
        cb.record_failure("aws");
        assert_eq!(cb.state("aws"), CircuitState::Closed);
    }

    #[test]
    fn test_success_closes_circuit() {
        let cb = CircuitBreaker::new(1, 60);
        cb.record_failure("openai");
        assert_eq!(cb.state("openai"), CircuitState::Open);
        cb.record_success("openai");
        assert_eq!(cb.state("openai"), CircuitState::Closed);
        assert!(cb.allow("openai"));
    }

    #[test]
    fn test_halfopen_failure_returns_to_open() {
        let cb = CircuitBreaker::new(3, 60);
        // Force open
        for _ in 0..3 {
            cb.record_failure("gitlab");
        }
        // Force to HalfOpen by manually tweaking last_failure
        {
            let mut states = cb.states.lock().unwrap();
            let entry = states.get_mut("gitlab").unwrap();
            // Pretend the cooldown has already elapsed
            entry.last_failure = Some(Instant::now() - Duration::from_secs(120));
        }
        // allow() should transition to HalfOpen and return true
        assert!(cb.allow("gitlab"));
        assert_eq!(cb.state("gitlab"), CircuitState::HalfOpen);

        // A failure in HalfOpen should immediately reopen
        cb.record_failure("gitlab");
        assert_eq!(cb.state("gitlab"), CircuitState::Open);
    }

    #[test]
    fn test_providers_are_independent() {
        let cb = CircuitBreaker::new(2, 60);
        cb.record_failure("anthropic");
        cb.record_failure("anthropic");
        assert_eq!(cb.state("anthropic"), CircuitState::Open);
        // huggingface should be unaffected
        assert_eq!(cb.state("huggingface"), CircuitState::Closed);
        assert!(cb.allow("huggingface"));
    }

    #[test]
    fn test_cooldown_transitions_to_halfopen() {
        let cb = CircuitBreaker::new(1, 1); // 1-second cooldown
        cb.record_failure("slack");
        assert_eq!(cb.state("slack"), CircuitState::Open);

        // Simulate cooldown by backdating last_failure
        {
            let mut states = cb.states.lock().unwrap();
            let entry = states.get_mut("slack").unwrap();
            entry.last_failure = Some(Instant::now() - Duration::from_secs(2));
        }

        assert!(
            cb.allow("slack"),
            "After cooldown, circuit should allow probe"
        );
        assert_eq!(cb.state("slack"), CircuitState::HalfOpen);
    }
}
