// Tipos de membros e sessões de uma sala Matrix

use std::collections::HashMap;
use crate::core::crypto::{OlmSessionHandle, MegolmInbound, KeyAgreementStats};
use super::crypto_backend::{CryptoMode, CryptoWrapper};

/// Identificador único de usuário Matrix
pub type UserId = String;

/// Sessões Olm bidirecionais com outro membro
pub struct OlmSessionPair {
    /// Sessão outbound para ENVIAR mensagens (criada com create_outbound_session)
    pub outbound: Option<OlmSessionHandle>,
    /// Sessão inbound para RECEBER mensagens (criada com create_inbound_session)
    pub inbound: Option<OlmSessionHandle>,
    /// KEM ciphertext pendente gerado por forced_ratchet no INBOUND para ser usado pelo OUTBOUND
    pub pending_kem_for_outbound: Option<Vec<u8>>,
}

impl OlmSessionPair {
    pub fn new() -> Self {
        Self {
            outbound: None,
            inbound: None,
            pending_kem_for_outbound: None,
        }
    }

    /// Verifica se tem sessão outbound estabelecida
    pub fn has_outbound(&self) -> bool {
        self.outbound.is_some()
    }

    /// Obtém sessão outbound mutável para enviar
    pub fn get_outbound_mut(&mut self) -> Option<&mut OlmSessionHandle> {
        self.outbound.as_mut()
    }

    /// Obtém sessão inbound mutável para receber
    pub fn get_inbound_mut(&mut self) -> Option<&mut OlmSessionHandle> {
        self.inbound.as_mut()
    }
}

/// Membro de uma sala Matrix
pub struct RoomMember {
    /// ID do usuário Matrix
    #[allow(dead_code)]
    pub user_id: UserId,
    /// Provedor criptográfico (híbrido ou clássico)
    pub crypto: CryptoWrapper,
    /// Sessões Olm com outros membros (outbound + inbound para cada peer)
    pub olm_sessions: HashMap<UserId, OlmSessionPair>,
    /// Sessão Megolm inbound atual (para descriptografia)
    pub megolm_inbound: Option<MegolmInbound>,
}

impl RoomMember {
    pub fn new_hybrid(user_id: UserId) -> Self {
        Self {
            user_id,
            crypto: CryptoWrapper::new_hybrid(),
            olm_sessions: HashMap::new(),
            megolm_inbound: None,
        }
    }

    pub fn new_classical(user_id: UserId) -> Self {
        Self {
            user_id,
            crypto: CryptoWrapper::new_classical(),
            olm_sessions: HashMap::new(),
            megolm_inbound: None,
        }
    }

    pub fn new(user_id: UserId, mode: CryptoMode) -> Self {
        match mode {
            CryptoMode::Hybrid => Self::new_hybrid(user_id),
            CryptoMode::Classical => Self::new_classical(user_id),
        }
    }
}

/// Estatísticas de uma sessão Megolm
#[derive(Debug, Default, Clone)]
pub struct MegolmSessionStats {
    pub creation_time_ms: f64,
    pub distribution_time_ms: f64,
    pub messages_encrypted: usize,
    pub total_bytes_encrypted: usize,
    #[allow(dead_code)]
    pub key_agreement_stats: KeyAgreementStats,
}
