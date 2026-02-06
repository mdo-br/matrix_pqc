// Sistema de logging com níveis de verbosidade
//
// Permite controlar a quantidade de output durante experimentos
// sem precisar recompilar o código.

use std::sync::atomic::{AtomicU8, Ordering};

/// Níveis de verbosidade
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum VerbosityLevel {
    /// Nenhum output (apenas resultados finais)
    Silent = 0,
    /// Output mínimo (apenas marcos importantes)
    Minimal = 1,
    /// Output normal (progresso + resultados)
    Normal = 2,
    /// Output detalhado (inclui operações individuais)
    Verbose = 3,
    /// Output máximo (debug completo)
    Debug = 4,
}

// Variável global atômica para controlar verbosidade
static VERBOSITY: AtomicU8 = AtomicU8::new(VerbosityLevel::Normal as u8);

/// Define o nível de verbosidade global
pub fn set_verbosity(level: VerbosityLevel) {
    VERBOSITY.store(level as u8, Ordering::Relaxed);
}

/// Obtém o nível de verbosidade atual
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

/// Verifica se deve logar no nível especificado
pub fn should_log(level: VerbosityLevel) -> bool {
    get_verbosity() >= level
}

/// Macro para log condicional baseado em verbosidade
#[macro_export]
macro_rules! vlog {
    // vlog!(Minimal, "mensagem")
    ($level:expr, $($arg:tt)*) => {
        if $crate::utils::logging::should_log($level) {
            println!($($arg)*);
        }
    };
}

/// Macro para log de progresso (sempre visível, menos em Silent)
#[macro_export]
macro_rules! progress {
    ($($arg:tt)*) => {
        if $crate::utils::logging::get_verbosity() > $crate::utils::logging::VerbosityLevel::Silent {
            println!($($arg)*);
        }
    };
}

/// Macro para log de resultados (sempre visível)
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
