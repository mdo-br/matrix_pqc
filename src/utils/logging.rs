//! Verbosity-based logging system for experiment output control.
//!
//! Controls the amount of output produced during experiments without recompiling.

use std::sync::atomic::{AtomicU8, Ordering};

/// Verbosity levels for log output filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum VerbosityLevel {
    /// No output (only final results).
    Silent = 0,
    /// Minimal output (only important milestones).
    Minimal = 1,
    /// Normal output (progress and results).
    Normal = 2,
    /// Detailed output (includes individual operations).
    Verbose = 3,
    /// Maximum output (full debug).
    Debug = 4,
}

// Global atomic variable controlling verbosity.
static VERBOSITY: AtomicU8 = AtomicU8::new(VerbosityLevel::Normal as u8);

/// Sets the global verbosity level.
pub fn set_verbosity(level: VerbosityLevel) {
    VERBOSITY.store(level as u8, Ordering::Relaxed);
}

/// Returns the current global verbosity level.
pub fn get_verbosity() -> VerbosityLevel {
    match VERBOSITY.load(Ordering::Relaxed) {
        0 => VerbosityLevel::Silent,
        1 => VerbosityLevel::Minimal,
        2 => VerbosityLevel::Normal,
        3 => VerbosityLevel::Verbose,
        4 => VerbosityLevel::Debug,
        _ => VerbosityLevel::Normal,
    }
}

/// Returns `true` if the given level should produce output at the current verbosity.
pub fn should_log(level: VerbosityLevel) -> bool {
    get_verbosity() >= level
}

/// Logs a message if the current verbosity is at or above `$level`.
#[macro_export]
macro_rules! vlog {
    // vlog!(Minimal, "mensagem")
    ($level:expr, $($arg:tt)*) => {
        if $crate::utils::logging::should_log($level) {
            println!($($arg)*);
        }
    };
}

/// Logs a progress message unless verbosity is `Silent`.
#[macro_export]
macro_rules! progress {
    ($($arg:tt)*) => {
        if $crate::utils::logging::get_verbosity() > $crate::utils::logging::VerbosityLevel::Silent {
            println!($($arg)*);
        }
    };
}

/// Logs a result message unconditionally.
#[macro_export]
macro_rules! result_log {
    ($($arg:tt)*) => {
        println!($($arg)*);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verbosity_levels() {
        set_verbosity(VerbosityLevel::Silent);
        assert_eq!(get_verbosity(), VerbosityLevel::Silent);
        assert!(!should_log(VerbosityLevel::Minimal));

        set_verbosity(VerbosityLevel::Normal);
        assert!(should_log(VerbosityLevel::Minimal));
        assert!(should_log(VerbosityLevel::Normal));
        assert!(!should_log(VerbosityLevel::Verbose));

        set_verbosity(VerbosityLevel::Debug);
        assert!(should_log(VerbosityLevel::Verbose));
        assert!(should_log(VerbosityLevel::Debug));
    }
}
