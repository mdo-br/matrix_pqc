//! Core cryptographic types and traits.
//!
//! Defines fundamental types, traits, and enums shared by all crypto provider
//! implementations (classical and hybrid PQC).

use anyhow::Result;
use serde::{Serialize, Deserialize};

/// CRYSTALS-Kyber (Round 3) security parameter variants.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum KemAlgorithm {
    /// Kyber-512 — NIST Level 1 (128-bit quantum security).
    Kyber512,
    /// Kyber-768 — NIST Level 3 (192-bit quantum security). Recommended default.
    Kyber768,
    /// Kyber-1024 — NIST Level 5 (256-bit quantum security).
    Kyber1024,
}

impl KemAlgorithm {
    pub fn name(&self) -> &'static str {
        match self {
            KemAlgorithm::Kyber512 => "Kyber-512",
            KemAlgorithm::Kyber768 => "Kyber-768",
            KemAlgorithm::Kyber1024 => "Kyber-1024",
        }
    }
}

/// Diagnostic methods — public API without internal consumers.
#[allow(dead_code)]
impl KemAlgorithm {
    pub fn security_level(&self) -> u16 {
        match self {
            KemAlgorithm::Kyber512 => 128,
            KemAlgorithm::Kyber768 => 192,
            KemAlgorithm::Kyber1024 => 256,
        }
    }
}

/// KEM variant selector for provider configuration.
///
/// Chooses the Kyber variant used in the Double Ratchet PQC.
/// The PQXDH handshake always uses Kyber-1024 regardless of this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemChoice {
    Kyber512,
    Kyber768,
    Kyber1024,
}

impl From<KemChoice> for KemAlgorithm {
    fn from(choice: KemChoice) -> Self {
        match choice {
            KemChoice::Kyber512 => KemAlgorithm::Kyber512,
            KemChoice::Kyber768 => KemAlgorithm::Kyber768,
            KemChoice::Kyber1024 => KemAlgorithm::Kyber1024,
        }
    }
}

impl From<KemAlgorithm> for KemChoice {
    fn from(alg: KemAlgorithm) -> Self {
        match alg {
            KemAlgorithm::Kyber512 => KemChoice::Kyber512,
            KemAlgorithm::Kyber768 => KemChoice::Kyber768,
            KemAlgorithm::Kyber1024 => KemChoice::Kyber1024,
        }
    }
}

/// Identity key bundle exported for upload to the Matrix homeserver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityKeysExport {
    /// Curve25519 public key for X3DH/ECDH.
    pub curve25519: String,
    /// Ed25519 public key for identity signatures.
    pub ed25519: String,
    /// KEM public key (hybrid mode only; `None` for classical).
    pub kem_pub_opt: Option<String>,
}

/// One-time key exported for upload to the Matrix homeserver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimeKeyExport {
    pub key_id: String,
    pub curve25519: String,
}

/// Olm session handle with optional PQC Double Ratchet.
///
/// Wraps a `HybridOlmSession` and tracks whether PQC mode is active.
pub struct OlmSessionHandle {
    pub hybrid_session: crate::core::double_ratchet_pqc::HybridOlmSession,
    pub pqc_enabled: bool,
    #[allow(dead_code)]
    pub kem_algorithm: Option<crate::core::crypto::KemAlgorithm>,
}

impl OlmSessionHandle {
    pub fn is_pqc_enabled(&self) -> bool {
        self.pqc_enabled
    }

    /// Returns the number of PQC ratchet advances (asymmetric rotations).
    pub fn get_ratchet_advances(&self) -> u32 {
        if self.pqc_enabled {
            let stats = self.hybrid_session.get_session_stats();
            stats.ratchet_stats.map(|s| s.ratchet_advances).unwrap_or(0)
        } else {
            0
        }
    }

    /// Returns the number of asymmetric (direction-change) ratchet steps.
    pub fn get_asymmetric_advances(&self) -> u32 {
        if self.pqc_enabled {
            let stats = self.hybrid_session.get_session_stats();
            stats.ratchet_stats.map(|s| s.asymmetric_advances).unwrap_or(0)
        } else {
            0
        }
    }

    /// Forces an asymmetric PQC ratchet step, generating fresh Kyber keys.
    /// Used before Megolm key rotation to advance PQC forward secrecy.
    /// No-op when PQC is disabled.
    pub fn force_asymmetric_ratchet_advance(&mut self) -> Result<(), CryptoError> {
        if self.pqc_enabled {
            self.hybrid_session.force_asymmetric_ratchet_advance()
        } else {
            Ok(())
        }
    }

    /// Returns `true` if the session has a peer PQC ratchet key established.
    pub fn has_peer_key(&self) -> bool {
        if self.pqc_enabled {
            self.hybrid_session.has_peer_key()
        } else {
            false
        }
    }

    /// Returns `true` if the underlying vodozemac session has decrypted at least one message.
    pub fn has_received_message_classic(&self) -> bool {
        self.hybrid_session.has_received_message_classic()
    }
}

/// Megolm outbound group session.
pub struct MegolmOutbound {
    pub inner: vodozemac::megolm::GroupSession,
}

/// Megolm inbound group session.
pub struct MegolmInbound {
    pub inner: vodozemac::megolm::InboundGroupSession,
}

/// Timing and size statistics for a single PQXDH key agreement.
#[derive(Debug, Clone, Default)]
pub struct KeyAgreementStats {
    pub kem_time_ms: f64,
    pub kem_bytes: usize,
    #[allow(dead_code)]
    pub hkdf_time_ms: f64,
    pub total_time_ms: f64,
}

/// Errors produced by cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key format")]
    KeyFormat,
    #[error("Cryptographic protocol error")]
    Protocol,
    #[error("Base64 encoding/decoding error")]
    B64,
}

/// Unified interface for Matrix crypto providers (classical and hybrid PQC).
pub trait CryptoProvider {
    fn account_new() -> Self where Self: Sized;

    fn set_hybrid_kem_peer_pks(&mut self, _peer_kem_pks_b64: &[String]) {}

    fn upload_identity_keys(&self) -> IdentityKeysExport;

    fn generate_one_time_keys(&mut self, count: usize) -> Vec<OneTimeKeyExport>;

    fn mark_keys_published(&mut self);

    /// Creates an outbound Olm session.
    /// Returns `(session, Some(init_message))` for hybrid mode, `(session, None)` for classical.
    fn create_outbound_session(
        &mut self,
        their_curve25519: &str,
        their_one_time_key: &str,
    ) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>), CryptoError>;

    /// Stores a PQXDH init message for use in the next `create_inbound_session` call.
    /// No-op in classical mode.
    fn set_pqxdh_init_message(&mut self, _init_message: crate::core::pqxdh::MatrixPqxdhInitMessage) {}

    /// Creates an inbound Olm session from a received PreKey message.
    /// In hybrid mode, requires `set_pqxdh_init_message` to have been called first.
    fn create_inbound_session(
        &mut self,
        their_curve25519: &str,
        prekey_message: &[u8],
    ) -> Result<(OlmSessionHandle, Vec<u8>), CryptoError>;

    fn olm_encrypt(&mut self, session: &mut OlmSessionHandle, plaintext: &[u8]) -> Vec<u8>;

    fn olm_decrypt(&mut self, session: &mut OlmSessionHandle, message: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn megolm_create_outbound(&mut self) -> MegolmOutbound;

    fn megolm_export_inbound(&self, room_key: &MegolmOutbound) -> Vec<u8>;

    fn megolm_import_inbound(&mut self, exported: &[u8]) -> MegolmInbound;

    fn megolm_encrypt(&mut self, outbound: &mut MegolmOutbound, plaintext: &[u8]) -> Vec<u8>;

    fn megolm_decrypt(&mut self, inbound: &mut MegolmInbound, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
}