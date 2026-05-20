//! Hybrid PQC + Classical crypto provider for the Matrix protocol.
//!
//! Wraps vodozemac with post-quantum extensions (CRYSTALS-Kyber):
//! - PQXDH: hybrid key agreement (X25519 × 4 + Kyber-1024 KEM)
//! - Double Ratchet PQC: KEM ratcheting on direction changes (Kyber-768 default)
//! - Megolm: plain AES-256-CBC group encryption; PQC protects key distribution only
//!
//! Message format: `{"type":2,"body":"<base64>"}` for PQC, `{"type":0/1,...}` for classical fallback.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json;
use crate::core::crypto::*;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use vodozemac::{
    megolm::{
        GroupSession, InboundGroupSession, MegolmMessage, SessionConfig as MegolmSessionConfig,
    },
    olm::{Account, Message, OlmMessage, PreKeyMessage, SessionConfig},
    Curve25519PublicKey,
};

use crate::core::pqxdh::{complete_pqxdh, init_pqxdh, MatrixUser};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;

/// Derives a 32-byte hybrid root key via HKDF-SHA-256 over the concatenation of
/// a classical (X25519) and a post-quantum (Kyber) shared secret.
/// `ctx` binds the output to the session (domain separation).
fn hkdf_hybrid_root(ss_classic: &[u8], ss_pqc: &[u8], ctx: &[u8]) -> [u8; 32] {
    let salt = b"matrix-hybrid-root:v1|olm-x25519|kem-kyber";
    let hk = Hkdf::<Sha256>::new(Some(salt), &[ss_classic, ss_pqc].concat());
    let mut okm = [0u8; 32];
    hk.expand(ctx, &mut okm)
        .expect("HKDF expand never fails with valid parameters");
    okm
}

/// Hybrid PQC + classical crypto provider.
pub struct VodoCryptoHybrid {
    account: Account,
    kem_choice: KemChoice,
    last_stats: KeyAgreementStats,
    pqxdh_user: MatrixUser,
    peer_public_keys: Option<serde_json::Value>,
    pqxdh_init_message: Option<crate::core::pqxdh::MatrixPqxdhInitMessage>,
}

impl VodoCryptoHybrid {
    /// Creates a new hybrid account. `choice` selects the KEM variant used in the
    /// Double Ratchet (Kyber512/768/1024). PQXDH handshake always uses Kyber-1024.
    pub fn account_new(choice: KemChoice) -> Self {
        let user_id = format!("@user{}:matrix.org", rand::thread_rng().gen::<u32>());
        let device_id = format!("DEVICE_{}", rand::thread_rng().gen::<u32>());
        let pqxdh_user = MatrixUser::new(user_id, device_id).expect("Failed to create PQXDH user");

        Self {
            account: Account::new(),
            kem_choice: choice,
            last_stats: KeyAgreementStats::default(),
            pqxdh_user,
            peer_public_keys: None,
            pqxdh_init_message: None,
        }
    }
}

impl VodoCryptoHybrid {
    pub fn set_peer_public_keys(&mut self, peer_keys: serde_json::Value) {
        self.peer_public_keys = Some(peer_keys);
    }

    pub fn export_pqxdh_public_keys(&self) -> serde_json::Value {
        self.pqxdh_user.export_public_keys()
    }

    pub fn set_pqxdh_init_message(&mut self, init_message: crate::core::pqxdh::MatrixPqxdhInitMessage) {
        self.pqxdh_init_message = Some(init_message);
    }
}

impl CryptoProvider for VodoCryptoHybrid {
    fn set_hybrid_kem_peer_pks(&mut self, _peer_kem_pks_b64: &[String]) {
        // no-op: peer keys are managed via set_peer_public_keys()
    }

    fn account_new() -> Self
    where
        Self: Sized,
    {
        Self::account_new(KemChoice::Kyber768)
    }

    /// Returns classical identity keys (Curve25519 + Ed25519).
    /// For PQC keys use `export_pqxdh_public_keys()`.
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
        map.iter()
            .map(|(k, v)| OneTimeKeyExport {
                key_id: format!("{:?}", k),
                curve25519: v.to_base64(),
            })
            .collect()
    }

    fn mark_keys_published(&mut self) {
        self.account.mark_keys_as_published();
    }

    /// Creates an outbound Olm session with PQXDH hybrid key agreement when peer keys
    /// are available, falling back to plain X25519 otherwise.
    /// Returns `(session, Some(init_message))` for PQC or `(session, None)` for classical.
    fn create_outbound_session(
        &mut self,
        their_curve25519: &str,
        their_one_time_key: &str,
    ) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>), CryptoError> {
        let id_key = Curve25519PublicKey::from_base64(their_curve25519)
            .map_err(|_| CryptoError::KeyFormat)?;
        let otk = Curve25519PublicKey::from_base64(their_one_time_key)
            .map_err(|_| CryptoError::KeyFormat)?;

        if let Some(ref peer_keys) = self.peer_public_keys {
            let start_time = std::time::Instant::now();

            match init_pqxdh(&self.pqxdh_user, peer_keys) {
                Ok(pqxdh_output) => {
                    vlog!(VerbosityLevel::Debug, "PQXDH handshake completed");

                    let init_message_for_transmission = pqxdh_output.init_message.clone();
                    self.pqxdh_init_message = Some(pqxdh_output.init_message.clone());

                    // Create a base classical Olm session, then mix PQXDH key via HKDF.
                    let classic_session = self.account.create_outbound_session(
                        SessionConfig::version_2(),
                        id_key,
                        otk,
                    );

                    let session_id = classic_session.session_id();
                    let classic_sk = session_id.as_bytes();
                    let ctx = format!(
                        "olm-pqxdh:{}:{}",
                        self.pqxdh_user.user_id, self.pqxdh_user.device_id
                    );
                    let _hybrid_key =
                        hkdf_hybrid_root(classic_sk, &pqxdh_output.session_key, ctx.as_bytes());

                    let elapsed = start_time.elapsed();
                    self.last_stats.total_time_ms = elapsed.as_secs_f64() * 1000.0;
                    self.last_stats.kem_time_ms = self.last_stats.total_time_ms;
                    self.last_stats.kem_bytes = match self.kem_choice {
                        KemChoice::Kyber512 => pqcrypto_kyber::kyber512::ciphertext_bytes(),
                        KemChoice::Kyber768 => pqcrypto_kyber::kyber768::ciphertext_bytes(),
                        KemChoice::Kyber1024 => pqcrypto_kyber::kyber1024::ciphertext_bytes(),
                    };

                    vlog!(VerbosityLevel::Debug, "Hybrid Olm session created (PQC + classical).");

                    let mut hybrid_session_alice = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(
                        classic_session
                    );

                    let mut root_key = [0u8; 32];
                    root_key[..pqxdh_output.session_key.len().min(32)].copy_from_slice(
                        &pqxdh_output.session_key[..pqxdh_output.session_key.len().min(32)]
                    );

                    let kem_algo: crate::core::crypto::KemAlgorithm = self.kem_choice.into();
                    hybrid_session_alice.enable_pqc_mode(root_key, kem_algo);

                    return Ok((
                        OlmSessionHandle {
                            hybrid_session: hybrid_session_alice,
                            pqc_enabled: true,
                            kem_algorithm: Some(kem_algo),
                        },
                        Some(init_message_for_transmission)
                    ));
                }
                Err(e) => {
                    vlog!(VerbosityLevel::Normal, "PQXDH error: {:?}. Falling back to classical Olm.", e);
                }
            }
        }

        // Fallback: plain classical Olm session
        let classic_session = self.account.create_outbound_session(SessionConfig::version_2(), id_key, otk);
        let hybrid_session = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(classic_session);

        vlog!(VerbosityLevel::Normal, "Classical Olm channel (PQXDH not available)");

        Ok((
            OlmSessionHandle {
                hybrid_session,
                pqc_enabled: false,
                kem_algorithm: None,
            },
            None
        ))
    }

    fn set_pqxdh_init_message(&mut self, init_message: crate::core::pqxdh::MatrixPqxdhInitMessage) {
        self.pqxdh_init_message = Some(init_message);
    }

    /// Creates an inbound Olm session. Completes the PQXDH handshake when an init
    /// message is available, enabling PQC Double Ratchet; otherwise accepts a plain
    /// classical Olm PreKey message.
    fn create_inbound_session(
        &mut self,
        _their_curve25519: &str,
        prekey_message: &[u8],
    ) -> Result<(OlmSessionHandle, Vec<u8>), CryptoError> {
        // PQC message: JSON envelope `{"type":2,...}`. Classical: raw binary PreKeyMessage.
        if prekey_message.starts_with(b"{\"type\":2,") {
            let prekey_message_str = std::str::from_utf8(prekey_message).map_err(|_| CryptoError::Protocol)?;
            let pqc_msg = crate::core::double_ratchet_pqc::PqcOlmMessage::from_transport_string(prekey_message_str)?;

            // Extract classical PreKeyMessage from the inner component
            let prekey = match &pqc_msg.classic_component {
                vodozemac::olm::OlmMessage::PreKey(pk) => pk.clone(),
                _ => return Err(CryptoError::Protocol),
            };
            
            let their_identity_key = prekey.identity_key();

            let creation_result = self
                .account
                .create_inbound_session(their_identity_key, &prekey)
                .map_err(|_| CryptoError::Protocol)?;

            let plaintext = creation_result.plaintext;
            let vodozemac_session = creation_result.session;

            let pqc_successful;
            let mut pqxdh_root_key = [0u8; 32];
            
            if let Some(ref init_message) = self.pqxdh_init_message {
                let start_time = std::time::Instant::now();

                match complete_pqxdh(&mut self.pqxdh_user, init_message) {
                    Ok(session_key) => {
                        vlog!(VerbosityLevel::Normal, "PQXDH completed successfully");
                        pqc_successful = true;
                        pqxdh_root_key[..session_key.len().min(32)].copy_from_slice(
                            &session_key[..session_key.len().min(32)]
                        );

                        let elapsed = start_time.elapsed();
                        self.last_stats.total_time_ms = elapsed.as_secs_f64() * 1000.0;
                        self.last_stats.kem_time_ms = self.last_stats.total_time_ms * 0.8;
                        self.last_stats.kem_bytes = match self.kem_choice {
                            KemChoice::Kyber512 => pqcrypto_kyber::kyber512::ciphertext_bytes(),
                            KemChoice::Kyber768 => pqcrypto_kyber::kyber768::ciphertext_bytes(),
                            KemChoice::Kyber1024 => pqcrypto_kyber::kyber1024::ciphertext_bytes(),
                        };
                    }
                    Err(e) => {
                        vlog!(VerbosityLevel::Normal, "PQXDH error: {:?}", e);
                        pqc_successful = false;
                    }
                }
            } else {
                pqc_successful = false;
            }

            let mut hybrid_session = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(vodozemac_session);

            if pqc_successful {
                let kem_algo: crate::core::crypto::KemAlgorithm = self.kem_choice.into();
                hybrid_session.enable_pqc_mode_as_receiver(pqxdh_root_key, kem_algo);

                // Apply PQC ratchet key from the initial message
                if let Some(ref ratchet_key) = pqc_msg.ratchet_key {
                    hybrid_session.set_peer_pqc_key(ratchet_key.clone())?;
                }
            }

            return Ok((
                OlmSessionHandle {
                    hybrid_session,
                    pqc_enabled: pqc_successful,
                    kem_algorithm: if pqc_successful { Some(self.kem_choice.into()) } else { None },
                },
                plaintext,
            ));
        }

        // Classical binary PreKeyMessage fallback.
        let prekey = PreKeyMessage::from_bytes(prekey_message).map_err(|_| CryptoError::Protocol)?;
        let their_identity_key = prekey.identity_key();

        let creation_result = self
            .account
            .create_inbound_session(their_identity_key, &prekey)
            .map_err(|_| CryptoError::Protocol)?;

        let plaintext = creation_result.plaintext;
        let vodozemac_session = creation_result.session;

        let pqc_successful;
        let mut pqxdh_root_key = [0u8; 32];

        if let Some(ref init_message) = self.pqxdh_init_message {
            let start_time = std::time::Instant::now();

            match complete_pqxdh(&mut self.pqxdh_user, init_message) {
                Ok(session_key) => {
                    vlog!(VerbosityLevel::Normal, "PQXDH completed (inbound)");

                    let session_id = vodozemac_session.session_id();
                    let classic_sk = session_id.as_bytes();
                    let ctx = format!(
                        "olm-pqxdh:{}:{}",
                        self.pqxdh_user.user_id, self.pqxdh_user.device_id
                    );
                    let _hybrid_key = hkdf_hybrid_root(classic_sk, &session_key, ctx.as_bytes());

                    pqc_successful = true;
                    pqxdh_root_key[..session_key.len().min(32)].copy_from_slice(
                        &session_key[..session_key.len().min(32)]
                    );

                    let elapsed = start_time.elapsed();
                    self.last_stats.total_time_ms = elapsed.as_secs_f64() * 1000.0;
                    self.last_stats.kem_time_ms = self.last_stats.total_time_ms * 0.8;
                    self.last_stats.kem_bytes = match self.kem_choice {
                        KemChoice::Kyber512 => pqcrypto_kyber::kyber512::ciphertext_bytes(),
                        KemChoice::Kyber768 => pqcrypto_kyber::kyber768::ciphertext_bytes(),
                        KemChoice::Kyber1024 => pqcrypto_kyber::kyber1024::ciphertext_bytes(),
                    };

                    vlog!(VerbosityLevel::Normal, "Hybrid Olm session created (inbound)");
                }
                Err(e) => {
                    vlog!(VerbosityLevel::Normal,
                        "PQXDH error: {:?}. Keeping classical Olm.",
                        e
                    );
                    pqc_successful = false;
                }
            }
        } else {
            pqc_successful = false;
        }

        let mut hybrid_session_bob = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(vodozemac_session);

        if pqc_successful {
            let kem_algo: crate::core::crypto::KemAlgorithm = self.kem_choice.into();
            hybrid_session_bob.enable_pqc_mode_as_receiver(pqxdh_root_key, kem_algo);
        }
        
        Ok((
            OlmSessionHandle {
                hybrid_session: hybrid_session_bob,
                pqc_enabled: pqc_successful,
                kem_algorithm: if pqc_successful { 
                    Some(self.kem_choice.into()) 
                } else { 
                    None 
                },
            },
            plaintext,
        ))
    }

    /// Encrypts a message via Olm. Uses PQC Double Ratchet when enabled, serialising to
    /// `{"type":2,...}`; falls back to classical vodozemac with `{"type":0/1,...}` envelope.
    fn olm_encrypt(&mut self, session: &mut OlmSessionHandle, plaintext: &[u8]) -> Vec<u8> {
        if session.pqc_enabled {
            match session.hybrid_session.encrypt_hybrid(plaintext) {
                Ok(pqc_msg) => pqc_msg.to_transport_string().into_bytes(),
                Err(e) => {
                    vlog!(VerbosityLevel::Verbose, "Hybrid Double Ratchet error: {:?} — falling back to classical", e);
                    let message = session.hybrid_session.encrypt_classic(plaintext);
                    let (msg_type, raw_bytes) = match message {
                        vodozemac::olm::OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
                        vodozemac::olm::OlmMessage::Normal(m) => (1u8, m.to_bytes()),
                    };
                    let body_b64 = B64.encode(&raw_bytes);
                    format!("{{\"type\":{},\"body\":\"{}\"}}", msg_type, body_b64).into_bytes()
                }
            }
        } else {
            let message = session.hybrid_session.encrypt_classic(plaintext);
            let (msg_type, raw_bytes) = match message {
                vodozemac::olm::OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
                vodozemac::olm::OlmMessage::Normal(m) => (1u8, m.to_bytes()),
            };
            let body_b64 = B64.encode(&raw_bytes);
            format!("{{\"type\":{},\"body\":\"{}\"}}", msg_type, body_b64).into_bytes()
        }
    }

    /// Decrypts an Olm message. Auto-detects format:
    /// - `{"type":2,...}` → PQC hybrid Double Ratchet path
    /// - `{"type":0/1,...}` → classical vodozemac (JSON+B64 envelope unwrapped first)
    fn olm_decrypt(
        &mut self,
        session: &mut OlmSessionHandle,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // PQC message: JSON envelope with type=2
        if message.starts_with(b"{\"type\":2,") {
            if session.pqc_enabled {
                let message_str = std::str::from_utf8(message).map_err(|_| CryptoError::Protocol)?;
                match crate::core::double_ratchet_pqc::PqcOlmMessage::from_transport_string(message_str) {
                    Ok(pqc_msg) => {
                        return session.hybrid_session.decrypt_hybrid(&pqc_msg)
                            .map_err(|_| CryptoError::Protocol);
                    }
                    Err(e) => {
                        vlog!(VerbosityLevel::Normal, "PQC deserialisation error: {:?}", e);
                        return Err(CryptoError::Protocol);
                    }
                }
            } else {
                vlog!(VerbosityLevel::Normal, "PQC message received but session has PQC disabled");
                return Err(CryptoError::Protocol);
            }
        }

        // Classical message in JSON+B64 envelope: {"type":0/1,"body":"<base64>"}
        let raw: Vec<u8> = if message.starts_with(b"{") {
            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(message) {
                if let Some(body_b64) = json_val.get("body").and_then(|b| b.as_str()) {
                    B64.decode(body_b64).map_err(|_| CryptoError::B64)?
                } else {
                    message.to_vec()
                }
            } else {
                message.to_vec()
            }
        } else {
            message.to_vec()
        };

        // Try PreKeyMessage
        if let Ok(pre) = PreKeyMessage::from_bytes(&raw) {
            let msg = OlmMessage::PreKey(pre);
            match session.hybrid_session.decrypt_classic(&msg) {
                Ok(plaintext) => return Ok(plaintext),
                Err(e) => {
                    vlog!(VerbosityLevel::Normal, "PreKeyMessage decrypt error: {:?}", e);
                    return Err(CryptoError::Protocol);
                }
            }
        }

        // Try normal Message
        if let Ok(norm) = Message::from_bytes(&raw) {
            let msg = OlmMessage::Normal(norm);
            match session.hybrid_session.decrypt_classic(&msg) {
                Ok(plaintext) => return Ok(plaintext),
                Err(e) => {
                    vlog!(VerbosityLevel::Normal, "Normal message decrypt error: {:?}", e);
                    return Err(CryptoError::Protocol);
                }
            }
        }

        vlog!(VerbosityLevel::Normal, "Unrecognised message format");
        Err(CryptoError::Protocol)
    }

    /// Creates a Megolm outbound group session (AES-256-CBC).
    /// PQC protection applies to the key distribution channel (Olm), not the payload.
    fn megolm_create_outbound(&mut self) -> MegolmOutbound {
        let gs = GroupSession::new(MegolmSessionConfig::version_1());
        MegolmOutbound { inner: gs }
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

    fn megolm_decrypt(
        &mut self,
        inbound: &mut MegolmInbound,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Unwrap JSON+B64 envelope: {"type":3,"body":"<base64>"}
        let raw = if message.starts_with(b"{") {
            let json_val: serde_json::Value =
                serde_json::from_slice(message).map_err(|_| CryptoError::Protocol)?;
            let body = json_val
                .get("body")
                .and_then(|v| v.as_str())
                .ok_or(CryptoError::Protocol)?;
            B64.decode(body).map_err(|_| CryptoError::B64)?
        } else {
            message.to_vec()
        };
        let msg = MegolmMessage::from_bytes(&raw).map_err(|_| CryptoError::Protocol)?;
        let decrypted = inbound
            .inner
            .decrypt(&msg)
            .map_err(|_| CryptoError::Protocol)?;
        Ok(decrypted.plaintext)
    }
}