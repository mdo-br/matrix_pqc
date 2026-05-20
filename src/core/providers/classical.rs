//! Classical (non-PQC) crypto provider for the Matrix protocol.
//!
//! Wraps vodozemac with no post-quantum extensions:
//! - Olm: X25519 key agreement + Double Ratchet (AES-256-CBC, HMAC-SHA-256)
//! - Megolm: AES-256-CBC group encryption with a forward-only ratchet
//!
//! Message format: `{"type":0/1,"body":"<base64>"}` for Olm, `{"type":3,...}` for Megolm.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::crypto::*;
use serde_json;
use vodozemac::{
    olm::{Account, SessionConfig, PreKeyMessage, Message, OlmMessage},
    megolm::{GroupSession, InboundGroupSession, MegolmMessage, SessionConfig as MegolmSessionConfig},
    Curve25519PublicKey,
};

/// Classical (vodozemac) crypto provider without PQC extensions.
pub struct VodoCrypto {
    account: Account,
}

impl CryptoProvider for VodoCrypto {
    fn account_new() -> Self {
        Self { account: Account::new() }
    }

    /// Returns the classical identity keys (Curve25519 + Ed25519).
    fn upload_identity_keys(&self) -> IdentityKeysExport {
        let id = self.account.identity_keys();
        IdentityKeysExport {
            curve25519: id.curve25519.to_base64(),
            ed25519: id.ed25519.to_base64(),
            kem_pub_opt: None,
        }
    }

    fn generate_one_time_keys(&mut self, count: usize) -> Vec<OneTimeKeyExport> {
        self.account.generate_one_time_keys(count);
        let map = self.account.one_time_keys();
        map.iter().map(|(k, v)| {
            OneTimeKeyExport { key_id: format!("{:?}", k), curve25519: v.to_base64() }
        }).collect()
    }

    fn mark_keys_published(&mut self) {
        self.account.mark_keys_as_published();
    }

    /// Creates an outbound Olm session via X3DH key agreement.
    /// Returns `(session, None)` — classical mode does not produce a PQXDH init message.
    fn create_outbound_session(
        &mut self,
        their_curve25519: &str,
        their_one_time_key: &str,
    ) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>), CryptoError> {
        let id_key = Curve25519PublicKey::from_base64(their_curve25519).map_err(|_| CryptoError::KeyFormat)?;
        let otk = Curve25519PublicKey::from_base64(their_one_time_key).map_err(|_| CryptoError::KeyFormat)?;
        let sess = self.account.create_outbound_session(SessionConfig::version_2(), id_key, otk);
        let hybrid_session = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(sess);
        Ok((
            OlmSessionHandle { 
                hybrid_session,
                pqc_enabled: false,
                kem_algorithm: None,
            },
            None
        ))
    }

    /// Creates an inbound Olm session from a received PreKey message.
    fn create_inbound_session(
        &mut self,
        _their_curve25519: &str,
        prekey_message: &[u8],
    ) -> Result<(OlmSessionHandle, Vec<u8>), CryptoError> {
        // Unwrap Matrix JSON+B64 envelope: {"type":N,"body":"<base64>"}
        let raw: Vec<u8> = if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(prekey_message) {
            if let Some(body_b64) = json_val.get("body").and_then(|b| b.as_str()) {
                B64.decode(body_b64).map_err(|_| CryptoError::B64)?
            } else {
                prekey_message.to_vec()
            }
        } else {
            prekey_message.to_vec()
        };
        let prekey = PreKeyMessage::from_bytes(&raw).map_err(|_| CryptoError::Protocol)?;
        let their_identity_key = prekey.identity_key();
        let creation_result = self.account.create_inbound_session(their_identity_key, &prekey)
            .map_err(|_| CryptoError::Protocol)?;
        let hybrid_session = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(creation_result.session);
        Ok((OlmSessionHandle { 
            hybrid_session, 
            pqc_enabled: false, 
            kem_algorithm: None 
        }, creation_result.plaintext))
    }

    fn olm_encrypt(&mut self, session: &mut OlmSessionHandle, plaintext: &[u8]) -> Vec<u8> {
        let message = session.hybrid_session.encrypt_classic(plaintext);
        // Serialise to Matrix JSON+B64 envelope: {"type":N,"body":"<base64>"}
        let (msg_type, raw_bytes) = match message {
            OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
            OlmMessage::Normal(m) => (1u8, m.to_bytes()),
        };
        let body_b64 = B64.encode(&raw_bytes);
        format!("{{\"type\":{},\"body\":\"{}\"}}", msg_type, body_b64).into_bytes()
    }

    fn olm_decrypt(&mut self, session: &mut OlmSessionHandle, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Unwrap Matrix JSON+B64 envelope: {"type":N,"body":"<base64>"}
        let raw: Vec<u8> = if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(message) {
            if let Some(body_b64) = json_val.get("body").and_then(|b| b.as_str()) {
                B64.decode(body_b64).map_err(|_| CryptoError::B64)?
            } else {
                message.to_vec()
            }
        } else {
            message.to_vec()
        };

        if let Ok(pre) = PreKeyMessage::from_bytes(&raw) {
            let msg = OlmMessage::PreKey(pre);
            return session.hybrid_session.decrypt_classic(&msg).map_err(|_| CryptoError::Protocol);
        }
        if let Ok(norm) = Message::from_bytes(&raw) {
            let msg = OlmMessage::Normal(norm);
            return session.hybrid_session.decrypt_classic(&msg).map_err(|_| CryptoError::Protocol);
        }
        Err(CryptoError::Protocol)
    }

    fn megolm_create_outbound(&mut self) -> MegolmOutbound {
        MegolmOutbound { inner: GroupSession::new(MegolmSessionConfig::version_1()) }
    }

    fn megolm_export_inbound(&self, room_key: &MegolmOutbound) -> Vec<u8> {
        let session_key = room_key.inner.session_key();
        session_key.to_bytes()
    }

    fn megolm_import_inbound(&mut self, exported: &[u8]) -> MegolmInbound {
        let session_key = vodozemac::megolm::SessionKey::from_bytes(exported).expect("session key");
        MegolmInbound {
            inner: InboundGroupSession::new(&session_key, MegolmSessionConfig::version_1()),
        }
    }

    fn megolm_encrypt(&mut self, outbound: &mut MegolmOutbound, plaintext: &[u8]) -> Vec<u8> {
        let msg = outbound.inner.encrypt(plaintext);
        let body_b64 = B64.encode(msg.to_bytes());
        format!("{{\"type\":3,\"body\":\"{}\"}}", body_b64).into_bytes()
    }

    fn megolm_decrypt(&mut self, inbound: &mut MegolmInbound, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Unwrap Matrix JSON+B64 envelope: {"type":3,"body":"<base64>"}
        let raw: Vec<u8> = if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(message) {
            if let Some(body_b64) = json_val.get("body").and_then(|b| b.as_str()) {
                B64.decode(body_b64).map_err(|_| CryptoError::B64)?
            } else {
                message.to_vec()
            }
        } else {
            message.to_vec()
        };
        let msg = MegolmMessage::from_bytes(&raw).map_err(|_| CryptoError::Protocol)?;
        let decrypted = inbound.inner.decrypt(&msg).map_err(|_| CryptoError::Protocol)?;
        Ok(decrypted.plaintext)
    }
}
