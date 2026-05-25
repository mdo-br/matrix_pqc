//! Megolm key rotation policies and configuration.

/// Megolm key rotation policy (presets for experiments).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RotationPolicy {
    /// Paranoid: maximum security (very frequent rotation).
    /// - 25 messages or 12 hours.
    /// - Rotate on any membership change.
    Paranoid,

    /// PQ3: inspired by Apple PQ3 (frequent rotation).
    /// - 50 messages or 1 day.
    /// - Rotate on membership changes.
    PQ3,

    /// Balanced: security/performance trade-off (Matrix default).
    /// - 100 messages or 7 days.
    /// - Rotate on membership changes.
    Balanced,

    /// Relaxed: performance-first (infrequent rotation).
    /// - 250 messages or 30 days.
    /// - No automatic rotation on membership changes.
    Relaxed,
}

impl RotationPolicy {
    /// Converts the policy into a concrete rotation configuration.
    pub fn to_config(&self) -> RotationConfig {
        match self {
            RotationPolicy::Paranoid => RotationConfig {
                max_messages: 25,
                max_age_ms: 12 * 3600 * 1000,
                rotate_on_member_join: true,
                rotate_on_member_leave: true,
            },
            RotationPolicy::PQ3 => RotationConfig {
                max_messages: 50,
                max_age_ms: 24 * 3600 * 1000,
                rotate_on_member_join: true,
                rotate_on_member_leave: true,
            },
            RotationPolicy::Balanced => RotationConfig {
                max_messages: 100,
                max_age_ms: 7 * 24 * 3600 * 1000,
                rotate_on_member_join: true,
                rotate_on_member_leave: true,
            },
            RotationPolicy::Relaxed => RotationConfig {
                max_messages: 250,
                max_age_ms: 30 * 24 * 3600 * 1000,
                rotate_on_member_join: false,
                rotate_on_member_leave: false,
            },
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        RotationPolicy::Balanced
    }
}

/// Megolm key rotation configuration.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Rotate after this many messages.
    pub max_messages: usize,
    /// Rotate after this many milliseconds.
    pub max_age_ms: u64,
    /// Rotate when a new member joins.
    pub rotate_on_member_join: bool,
    /// Rotate when a member leaves.
    #[allow(dead_code)]
    pub rotate_on_member_leave: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        RotationPolicy::Balanced.to_config()
    }
}
