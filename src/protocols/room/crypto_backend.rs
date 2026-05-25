//! Unified cryptographic provider for Matrix rooms.

use anyhow::Result;
use crate::core::{
    crypto::{CryptoProvider, CryptoError, OlmSessionHandle, MegolmOutbound, MegolmInbound,
             IdentityKeysExport, OneTimeKeyExport},
};
use crate::core::providers::hybrid::VodoCryptoHybrid;
use crate::core::providers::classical::VodoCrypto;

/// Room cryptographic mode.
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoMode {
    /// Hybrid mode: CRYSTALS-Kyber + X25519.
    Hybrid,
    /// Classical mode: X25519 only.
    Classical,
}

/// Unified cryptographic provider (hybrid or classical).
pub enum CryptoWrapper {
    Hybrid(VodoCryptoHybrid),
    Classical(VodoCrypto),
}

impl CryptoWrapper {
    pub fn new_hybrid() -> Self {
        Self::Hybrid(CryptoProvider::account_new())
    }

    pub fn new_classical() -> Self {
        Self::Classical(CryptoProvider::account_new())
    }

    pub fn upload_identity_keys(&self) -> IdentityKeysExport {
        match self {
            Self::Hybrid(crypto) => crypto.upload_identity_keys(),
            Self::Classical(crypto) => crypto.upload_identity_keys(),
        }
    }

    pub fn megolm_create_outbound(&mut self) -> MegolmOutbound {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_create_outbound(),
            Self::Classical(crypto) => crypto.megolm_create_outbound(),
        }
    }

    pub fn megolm_export_inbound(&mut self, outbound: &MegolmOutbound) -> Vec<u8> {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_export_inbound(outbound),
            Self::Classical(crypto) => crypto.megolm_export_inbound(outbound),
        }
    }

    pub fn megolm_import_inbound(&mut self, session_key: &[u8]) -> MegolmInbound {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_import_inbound(session_key),
            Self::Classical(crypto) => crypto.megolm_import_inbound(session_key),
        }
    }

    pub fn megolm_encrypt(&mut self, session: &mut MegolmOutbound, plaintext: &[u8]) -> Vec<u8> {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_encrypt(session, plaintext),
            Self::Classical(crypto) => crypto.megolm_encrypt(session, plaintext),
        }
    }

    pub fn megolm_decrypt(&mut self, session: &mut MegolmInbound, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_decrypt(session, ciphertext),
            Self::Classical(crypto) => crypto.megolm_decrypt(session, ciphertext),
        }
    }

    pub fn set_pqxdh_init_message(&mut self, init_message: crate::core::pqxdh::MatrixPqxdhInitMessage) {
        match self {
            Self::Hybrid(crypto) => crypto.set_pqxdh_init_message(init_message),
            Self::Classical(crypto) => crypto.set_pqxdh_init_message(init_message),
        }
    }

    pub fn olm_encrypt(&mut self, session: &mut OlmSessionHandle, plaintext: &[u8]) -> Vec<u8> {
        match self {
            Self::Hybrid(crypto) => crypto.olm_encrypt(session, plaintext),
            Self::Classical(crypto) => crypto.olm_encrypt(session, plaintext),
        }
    }

    pub fn olm_decrypt(&mut self, session: &mut OlmSessionHandle, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Hybrid(crypto) => crypto.olm_decrypt(session, ciphertext),
            Self::Classical(crypto) => crypto.olm_decrypt(session, ciphertext),
        }
    }

    pub fn generate_one_time_keys(&mut self, count: usize) -> Vec<OneTimeKeyExport> {
        match self {
            Self::Hybrid(crypto) => crypto.generate_one_time_keys(count),
            Self::Classical(crypto) => crypto.generate_one_time_keys(count),
        }
    }

    pub fn mark_keys_published(&mut self) {
        match self {
            Self::Hybrid(crypto) => crypto.mark_keys_published(),
            Self::Classical(crypto) => crypto.mark_keys_published(),
        }
    }

    pub fn create_inbound_session(&mut self, their_curve25519: &str, prekey_message: &[u8]) -> Result<(OlmSessionHandle, Vec<u8>), CryptoError> {
        match self {
            Self::Hybrid(crypto) => crypto.create_inbound_session(their_curve25519, prekey_message),
            Self::Classical(crypto) => crypto.create_inbound_session(their_curve25519, prekey_message),
        }
    }

    pub fn export_pqxdh_public_keys(&self) -> Option<serde_json::Value> {
        if let Self::Hybrid(crypto) = self {
            Some(crypto.export_pqxdh_public_keys())
        } else {
            None
        }
    }
}
