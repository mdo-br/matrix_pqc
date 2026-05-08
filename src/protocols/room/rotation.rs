// Políticas e configuração de rotação de chaves Megolm

/// Política de rotação de chaves Megolm (presets para experimentos)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RotationPolicy {
    /// Paranoid: Máxima segurança (rotação muito frequente)
    /// - 25 mensagens ou 12 horas
    /// - Rotação em qualquer mudança de membros
    Paranoid,

    /// PQ3: Inspirado no Apple PQ3 (rotação frequente)
    /// - 50 mensagens ou 1 dia
    /// - Rotação em mudanças de membros
    PQ3,

    /// Balanced: Equilíbrio segurança/performance (padrão Matrix)
    /// - 100 mensagens ou 7 dias
    /// - Rotação em mudanças de membros
    Balanced,

    /// Relaxed: Desempenho prioritário (rotação espaçada)
    /// - 250 mensagens ou 30 dias
    /// - Sem rotação automática em mudanças de membros
    Relaxed,
}

impl RotationPolicy {
    /// Converte política para configuração concreta
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

/// Configuração de rotação de chaves Megolm
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Rotação a cada N mensagens
    pub max_messages: usize,
    /// Rotação a cada N milissegundos (simulando dias)
    pub max_age_ms: u64,
    /// Rotação quando novo membro entra
    pub rotate_on_member_join: bool,
    /// Rotação quando membro sai
    #[allow(dead_code)]
    pub rotate_on_member_leave: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        RotationPolicy::Balanced.to_config()
    }
}
