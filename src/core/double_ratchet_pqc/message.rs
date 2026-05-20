//! Hybrid PQC message type (`PqcOlmMessage`) with Matrix-compatible serialization.

use crate::core::crypto::CryptoError;
use vodozemac::olm::{OlmMessage, Message, PreKeyMessage};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::keys::PqcRatchetPublicKey;

/// Hybrid Olm message wrapping a vodozemac `OlmMessage` with PQC extensions.
///
/// Maintains full Matrix protocol compatibility while adding the fields required
/// for the hybrid Double Ratchet (ratchet public key + KEM ciphertext).
///
/// # Wire format
/// `{"type":2,"body":"<base64>"}` where the Base64 payload is:
/// `[1 B version] [1 B classic_type] [4+N B classic] [4 B idx] [1 B pqc_flag]`
/// `[4+K B ratchet_key] [4+C B kem_ciphertext]`
///
/// Overhead: ~40 B on symmetric advances; ~800–1600 B on asymmetric advances
/// (ratchet_key + kem_ciphertext).
#[derive(Clone)]
pub struct PqcOlmMessage {
    /// Classic vodozemac message (base component).
    pub classic_component: OlmMessage,
    /// Current ratchet public key (sent in every message).
    pub ratchet_key: Option<PqcRatchetPublicKey>,
    /// KEM ciphertext produced by `encapsulate()`.
    /// Must be present on asymmetric advances so the receiver can call `decapsulate()`.
    pub kem_ciphertext: Option<Vec<u8>>,
    /// Indicates that PQC extensions are active on this session.
    pub pqc_enabled: bool,
    /// Message counter for ordering verification.
    pub message_index: u32,
}

impl PqcOlmMessage {
    /// Creates a PQC message from a classic component
    pub fn from_classic(classic: OlmMessage, message_index: u32) -> Self {
        Self {
            classic_component: classic,
            ratchet_key: None,
            kem_ciphertext: None,
            pqc_enabled: false,
            message_index,
        }
    }

    /// Attaches a PQC component to the message
    pub fn with_pqc_ratchet(mut self, ratchet_key: PqcRatchetPublicKey) -> Self {
        self.ratchet_key = Some(ratchet_key);
        self.pqc_enabled = true;
        self
    }

    /// Serializes the hybrid message to Matrix-compatible JSON.
    ///
    /// Produces `{"type":2,"body":"<base64>"}`. A single Base64 layer covers the
    /// full binary payload, avoiding double encoding.
    pub fn to_transport_string(&self) -> String {
        let (classic_type, classic_bytes) = match &self.classic_component {
            OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
            OlmMessage::Normal(m) => (1u8, m.to_bytes()),
        };

        let mut payload = Vec::new();

        // 1. PQC version
        payload.push(1u8);

        // 2. Classic message type
        payload.push(classic_type);

        // 3. Classic message size and data
        payload.extend_from_slice(&(classic_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(&classic_bytes);

        // 4. PQC metadata
        payload.extend_from_slice(&self.message_index.to_le_bytes());
        let pqc_enabled_byte = if self.pqc_enabled { 1 } else { 0 };
        vlog!(
            VerbosityLevel::Debug,
            "[SERIALIZE] pqc_enabled={}, byte={}, ratchet_key.is_some()={}",
            self.pqc_enabled,
            pqc_enabled_byte,
            self.ratchet_key.is_some()
        );
        payload.push(pqc_enabled_byte);

        // 5. PQC ratchet key (if available)
        if let Some(ref ratchet_key) = self.ratchet_key {
            let ratchet_bytes = ratchet_key.to_bytes();
            payload.extend_from_slice(&(ratchet_bytes.len() as u32).to_le_bytes());
            payload.extend_from_slice(&ratchet_bytes);
        } else {
            payload.extend_from_slice(&0u32.to_le_bytes());
        }

        // 6. KEM ciphertext (only present on asymmetric advances)
        if let Some(ref kem_ct) = self.kem_ciphertext {
            payload.extend_from_slice(&(kem_ct.len() as u32).to_le_bytes());
            payload.extend_from_slice(kem_ct);
            vlog!(
                VerbosityLevel::Debug,
                "[SERIALIZE] Incluindo KEM ciphertext ({} bytes)",
                kem_ct.len()
            );
        } else {
            payload.extend_from_slice(&0u32.to_le_bytes());
        }

        let body_b64 = B64.encode(&payload);
        vlog!(
            VerbosityLevel::Debug,
            "[SERIALIZE] Payload total: {} bytes",
            payload.len()
        );

        format!(r#"{{"type":2,"body":"{}"}}"#, body_b64)
    }

    /// Reconstructs the hybrid message from Matrix JSON
    pub fn from_transport_string(transport: &str) -> Result<Self, CryptoError> {
        let transport = transport.trim();
        if !transport.starts_with(r#"{"type":2,"#) {
            vlog!(
                VerbosityLevel::Debug,
                "[DESERIALIZE] Mensagem não começa com {{\"type\":2,"
            );
            return Err(CryptoError::Protocol);
        }

        let body_start = transport
            .find(r#""body":"#)
            .ok_or(CryptoError::Protocol)?
            + 8;
        let body_end = transport.rfind(r#""}"#).ok_or(CryptoError::Protocol)?;

        if body_start >= body_end {
            return Err(CryptoError::Protocol);
        }

        let body_b64 = &transport[body_start..body_end];
        let bytes = B64.decode(body_b64).map_err(|e| {
            vlog!(VerbosityLevel::Debug, "[DESERIALIZE] Erro Base64: {:?}", e);
            CryptoError::B64
        })?;

        if bytes.len() < 11 {
            return Err(CryptoError::Protocol);
        }

        let mut cursor = 0;

        // 1. PQC version
        let pqc_version = bytes[cursor];
        if pqc_version != 1 {
            return Err(CryptoError::Protocol);
        }
        cursor += 1;

        // 2. Classic message type
        let classic_type = bytes[cursor];
        cursor += 1;

        // 3. Classic component
        let classic_size = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| CryptoError::Protocol)?,
        ) as usize;
        cursor += 4;

        if cursor + classic_size > bytes.len() {
            return Err(CryptoError::Protocol);
        }

        let classic_bytes = &bytes[cursor..cursor + classic_size];
        cursor += classic_size;

        let classic_component = match classic_type {
            0 => OlmMessage::PreKey(
                PreKeyMessage::from_bytes(classic_bytes).map_err(|_| CryptoError::Protocol)?,
            ),
            1 => OlmMessage::Normal(
                Message::from_bytes(classic_bytes).map_err(|_| CryptoError::Protocol)?,
            ),
            _ => return Err(CryptoError::Protocol),
        };

        // 4. PQC metadata
        if cursor + 5 > bytes.len() {
            return Err(CryptoError::Protocol);
        }

        let message_index = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| CryptoError::Protocol)?,
        );
        cursor += 4;

        let pqc_enabled = bytes[cursor] != 0;
        cursor += 1;

        // 5. PQC ratchet key
        if cursor + 4 > bytes.len() {
            return Err(CryptoError::Protocol);
        }

        let ratchet_key_size = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| CryptoError::Protocol)?,
        ) as usize;
        cursor += 4;

        let ratchet_key = if ratchet_key_size > 0 {
            if cursor + ratchet_key_size > bytes.len() {
                return Err(CryptoError::Protocol);
            }
            let ratchet_bytes = &bytes[cursor..cursor + ratchet_key_size];
            cursor += ratchet_key_size;
            Some(PqcRatchetPublicKey::from_bytes(ratchet_bytes)?)
        } else {
            None
        };

        // 6. KEM ciphertext
        let kem_ciphertext = if cursor + 4 <= bytes.len() {
            let kem_ct_size = u32::from_le_bytes(
                bytes[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| CryptoError::Protocol)?,
            ) as usize;
            cursor += 4;

            if kem_ct_size > 0 {
                if cursor + kem_ct_size > bytes.len() {
                    return Err(CryptoError::Protocol);
                }
                let kem_ct = bytes[cursor..cursor + kem_ct_size].to_vec();
                vlog!(
                    VerbosityLevel::Debug,
                    "[DESERIALIZE] KEM ciphertext recuperado ({} bytes)",
                    kem_ct.len()
                );
                Some(kem_ct)
            } else {
                None
            }
        } else {
            None
        };

        Ok(PqcOlmMessage {
            classic_component,
            ratchet_key,
            kem_ciphertext,
            pqc_enabled,
            message_index,
        })
    }
}
