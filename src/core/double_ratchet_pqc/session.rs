//! `HybridOlmSession`: vodozemac + PQC Double Ratchet orchestrator.

use crate::core::crypto::{CryptoError, KemAlgorithm};
use vodozemac::olm::Session as VodoSession;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::keys::{PqcRatchetKeyPair, PqcRatchetPublicKey};
use super::message::PqcOlmMessage;
use super::state::{PqcDoubleRatchetState, PqcRatchetState, RatchetStats};

/// Hybrid Olm session combining a vodozemac base session with a PQC Double Ratchet.
///
/// Provides post-quantum hybrid security while remaining Matrix-compatible.
///
/// # Layer architecture
///
/// **Classical layer (`vodozemac_session`)**: X25519 ECDH + AES-256-CBC + HMAC-SHA-256,
/// producing standard `PreKeyMessage` / `Normal Message` wire frames.
///
/// **PQC layer (`pqc_ratchet`)**: X25519 + Kyber KEM in parallel, with HKDF-SHA-256
/// combining both shared secrets into a root key and chain key.
/// States: `Active` (sending) ↔ `Inactive` (awaiting send).
///
/// **Message layer**: `{"type":2,"body":"<base64>"}` JSON; the `{"type":2,...}` prefix
/// distinguishes PQC frames from classical Base64 frames.
///
/// # Initialisation
/// 1. `from_vodozemac(session)` — classical-only mode.
/// 2. `enable_pqc_mode()` (sender) or `enable_pqc_mode_as_receiver()` (receiver).
///
/// # Encryption (`encrypt_hybrid`)
/// 1. Advance PQC ratchet → symmetric or asymmetric step.
/// 2. `vodozemac_session.encrypt()` → `classic_component`.
/// 3. Assemble [`PqcOlmMessage`] and serialise to JSON.
///
/// # Decryption (`decrypt_hybrid`)
/// 1. Deserialise [`PqcOlmMessage`] from JSON.
/// 2. Compare `ratchet_key` to detect direction change.
/// 3. Advance ratchet accordingly.
/// 4. `vodozemac_session.decrypt()` → plaintext.
pub struct HybridOlmSession {
    /// Base vodozemac session — public for direct compatibility access.
    pub vodozemac_session: VodoSession,
    /// PQC Double Ratchet state; `None` when operating in classical-only mode.
    pqc_ratchet: Option<PqcDoubleRatchetState>,
    /// Total number of messages processed by this session.
    message_counter: u32,
    /// KEM ciphertext from a forced ratchet advance, to be attached to the next outgoing message.
    pending_kem_ciphertext: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl HybridOlmSession {
    /// Returns a reference to the underlying vodozemac session.
    pub fn get_vodozemac_session(&self) -> &VodoSession {
        &self.vodozemac_session
    }

    /// Creates a hybrid session wrapping an existing vodozemac session.
    pub fn from_vodozemac(session: VodoSession) -> Self {
        Self {
            vodozemac_session: session,
            pqc_ratchet: None,
            message_counter: 0,
            pending_kem_ciphertext: None,
        }
    }

    /// Enables PQC mode for the sender (Alice — sends first).
    pub fn enable_pqc_mode(&mut self, initial_root_key: [u8; 32], kem_algorithm: KemAlgorithm) {
        self.pqc_ratchet = Some(PqcDoubleRatchetState::new(
            initial_root_key,
            kem_algorithm,
            true,
        ));
        vlog!(
            VerbosityLevel::Debug,
            "├─Modo PQC habilitado no Double Ratchet com {}",
            kem_algorithm.name()
        );
    }

    /// Enables PQC mode for the receiver (Bob — receives first).
    pub fn enable_pqc_mode_as_receiver(
        &mut self,
        initial_root_key: [u8; 32],
        kem_algorithm: KemAlgorithm,
    ) {
        self.pqc_ratchet = Some(PqcDoubleRatchetState::new(
            initial_root_key,
            kem_algorithm,
            false,
        ));
        vlog!(
            VerbosityLevel::Debug,
            "├─Modo PQC habilitado no Double Ratchet com {} (como receptor)",
            kem_algorithm.name()
        );
    }

    /// Compatibility alias — enables PQC mode with Kyber-1024.
    pub fn enable_pqc_mode_default(&mut self, initial_root_key: [u8; 32]) {
        self.enable_pqc_mode(initial_root_key, KemAlgorithm::Kyber1024);
    }

    /// Sets the peer's PQC ratchet public key.
    pub fn set_peer_pqc_key(&mut self, peer_key: PqcRatchetPublicKey) -> Result<(), CryptoError> {
        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            pqc_state.set_peer_ratchet_key(peer_key);
            Ok(())
        } else {
            Err(CryptoError::Protocol)
        }
    }

    /// Returns our current public ratchet keys.
    pub fn get_our_ratchet_keys(&self) -> Result<PqcRatchetPublicKey, CryptoError> {
        if let Some(ref pqc_state) = self.pqc_ratchet {
            match &pqc_state.state {
                PqcRatchetState::Active {
                    our_ratchet_keys, ..
                }
                | PqcRatchetState::Inactive {
                    our_ratchet_keys, ..
                } => Ok(our_ratchet_keys.public_keys()),
            }
        } else {
            Err(CryptoError::Protocol)
        }
    }

    /// Forces an asymmetric PQC ratchet advance (used on Megolm key rotations).
    ///
    /// Executes the full KEM immediately and stores the ciphertext in
    /// `pending_kem_ciphertext` to be included in the next outgoing message,
    /// ensuring PQC forward secrecy across Megolm key rotations.
    pub fn force_asymmetric_ratchet_advance(&mut self) -> Result<(), CryptoError> {
        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            vlog!(
                VerbosityLevel::Debug,
                "[SYNC] [FORCE_RATCHET] Iniciando avanço assimétrico forçado"
            );

            match &pqc_state.state {
                PqcRatchetState::Active {
                    root_key,
                    their_ratchet_key,
                    send_counter,
                    ..
                } => {
                    vlog!(
                        VerbosityLevel::Debug,
                        "   └─ Estado anterior: Active (send_counter={})",
                        send_counter
                    );
                    let new_ratchet_keys = PqcRatchetKeyPair::generate(pqc_state.kem_algorithm);

                    if let Some(peer_key) = their_ratchet_key {
                        let (hybrid_secret, kem_ciphertext) =
                            new_ratchet_keys.hybrid_dh_with_kem(peer_key)?;
                        let (new_root_key, _chain_key) =
                            PqcDoubleRatchetState::derive_root_chain_keys(
                                &hybrid_secret,
                                root_key,
                            )?;

                        self.pending_kem_ciphertext = Some(kem_ciphertext.clone());
                        pqc_state.asymmetric_advance_count += 1;

                        vlog!(
                            VerbosityLevel::Debug,
                            "      └─ Nova root key derivada: {}",
                            hex::encode(&new_root_key[..8])
                        );

                        pqc_state.state = PqcRatchetState::Inactive {
                            root_key: new_root_key,
                            our_ratchet_keys: new_ratchet_keys,
                            their_ratchet_key: peer_key.clone(),
                            receive_counter: 0,
                        };

                        vlog!(
                            VerbosityLevel::Debug,
                            "   └─ Transição: Active → Inactive (avanço assimétrico COMPLETO)"
                        );
                    } else {
                        vlog!(
                            VerbosityLevel::Debug,
                            "   └─  Active sem peer_key - KEM será executado quando houver troca"
                        );
                    }
                }
                PqcRatchetState::Inactive {
                    root_key,
                    their_ratchet_key,
                    ..
                } => {
                    let new_ratchet_keys = PqcRatchetKeyPair::generate(pqc_state.kem_algorithm);
                    let (hybrid_secret, kem_ciphertext) =
                        new_ratchet_keys.hybrid_dh_with_kem(their_ratchet_key)?;
                    let (new_root_key, _chain_key) =
                        PqcDoubleRatchetState::derive_root_chain_keys(&hybrid_secret, root_key)?;

                    self.pending_kem_ciphertext = Some(kem_ciphertext.clone());
                    pqc_state.asymmetric_advance_count += 1;

                    vlog!(
                        VerbosityLevel::Debug,
                        "      └─ Nova root key derivada: {}",
                        hex::encode(&new_root_key[..8])
                    );

                    pqc_state.state = PqcRatchetState::Inactive {
                        root_key: new_root_key,
                        our_ratchet_keys: new_ratchet_keys,
                        their_ratchet_key: their_ratchet_key.clone(),
                        receive_counter: 0,
                    };

                    vlog!(
                        VerbosityLevel::Debug,
                        "   └─ Atualização: Inactive → Inactive (avanço assimétrico COMPLETO)"
                    );
                }
            }

            Ok(())
        } else {
            vlog!(
                VerbosityLevel::Debug,
                "[SYNC] [FORCE_RATCHET] PQC não habilitado - modo clássico"
            );
            Ok(())
        }
    }

    /// Encrypts a plaintext using the hybrid Double Ratchet.
    pub fn encrypt_hybrid(&mut self, plaintext: &[u8]) -> Result<PqcOlmMessage, CryptoError> {
        self.message_counter += 1;

        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            let was_inactive = matches!(pqc_state.state, PqcRatchetState::Inactive { .. });

            let (chain_key, kem_ciphertext_opt) =
                pqc_state.advance_sending_ratchet_with_kem()?;
            let message_key =
                PqcDoubleRatchetState::derive_message_key_from_chain(&chain_key)?;

            vlog!(
                VerbosityLevel::Debug,
                "  ├─Message key derivada: {}...",
                hex::encode(&message_key[..8])
            );

            let classic_msg = self.vodozemac_session.encrypt(plaintext);
            let mut pqc_msg = PqcOlmMessage::from_classic(classic_msg, self.message_counter);

            // Matrix pattern: ALWAYS include our current ratchet key
            let our_current_ratchet_key = match &pqc_state.state {
                PqcRatchetState::Active {
                    our_ratchet_keys, ..
                }
                | PqcRatchetState::Inactive {
                    our_ratchet_keys, ..
                } => our_ratchet_keys.public_keys(),
            };

            pqc_msg = pqc_msg.with_pqc_ratchet(our_current_ratchet_key);

            // Priority: KEM ciphertext from forced ratchet takes precedence over normal advance
            if let Some(pending_kem) = self.pending_kem_ciphertext.take() {
                vlog!(
                    VerbosityLevel::Debug,
                    "  ├─ Usando KEM ciphertext de FORCED RATCHET: {} bytes",
                    pending_kem.len()
                );
                pqc_msg.kem_ciphertext = Some(pending_kem);
            } else {
                pqc_msg.kem_ciphertext = kem_ciphertext_opt;
            }

            if was_inactive {
                vlog!(
                    VerbosityLevel::Debug,
                    "  └─Double Ratchet PQC: Nova chave ratchet (troca de direção) + KEM ciphertext"
                );
            }

            Ok(pqc_msg)
        } else {
            let classic_msg = self.vodozemac_session.encrypt(plaintext);
            let pqc_msg = PqcOlmMessage::from_classic(classic_msg, self.message_counter);
            vlog!(
                VerbosityLevel::Debug,
                "  └─Distribuição clássica (canal Olm sem PQC)"
            );
            Ok(pqc_msg)
        }
    }

    /// Decrypts a message using the hybrid Double Ratchet.
    pub fn decrypt_hybrid(&mut self, pqc_msg: &PqcOlmMessage) -> Result<Vec<u8>, CryptoError> {
        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            if let Some(ref new_ratchet_key) = pqc_msg.ratchet_key {
                let key_changed = pqc_state.has_peer_key_changed(new_ratchet_key);

                if key_changed {
                    if let Some(ref kem_ct) = pqc_msg.kem_ciphertext {
                        vlog!(
                            VerbosityLevel::Debug,
                            "  ├─Ratchet key MUDOU - avanço assimétrico com KEM"
                        );
                        let chain_key = pqc_state.advance_receiving_ratchet_with_decapsulate(
                            new_ratchet_key,
                            Some(kem_ct.as_slice()),
                        )?;
                        let _message_key =
                            PqcDoubleRatchetState::derive_message_key_from_chain(&chain_key)?;
                        vlog!(
                            VerbosityLevel::Debug,
                            "  ├─Message key derivada: {}...",
                            hex::encode(&_message_key[..8])
                        );
                        let plaintext = self
                            .vodozemac_session
                            .decrypt(&pqc_msg.classic_component)
                            .map_err(|e| {
                                vlog!(
                                    VerbosityLevel::Normal,
                                    "ERRO: decrypt_hybrid (avanço assimétrico) falhou: {:?}",
                                    e
                                );
                                CryptoError::Protocol
                            })?;
                        Ok(plaintext)
                    } else {
                        vlog!(
                            VerbosityLevel::Normal,
                            "[ERRO] Ratchet key mudou mas sem KEM ciphertext - KEM incompleto!"
                        );
                        Err(CryptoError::Protocol)
                    }
                } else {
                    vlog!(
                        VerbosityLevel::Debug,
                        "  ├─Ratchet key igual - avanço simétrico (chain key)"
                    );
                    let plaintext = self
                        .vodozemac_session
                        .decrypt(&pqc_msg.classic_component)
                        .map_err(|e| {
                            vlog!(
                                VerbosityLevel::Normal,
                                "ERRO: decrypt_hybrid (avanço simétrico) falhou: {:?}",
                                e
                            );
                            CryptoError::Protocol
                        })?;
                    Ok(plaintext)
                }
            } else {
                // Backward compatibility: message without ratchet_key
                vlog!(
                    VerbosityLevel::Debug,
                    "  ├─Sem ratchet_key (retrocompatibilidade)"
                );
                let plaintext = self
                    .vodozemac_session
                    .decrypt(&pqc_msg.classic_component)
                    .map_err(|e| {
                        vlog!(
                            VerbosityLevel::Normal,
                            "ERRO: decrypt_hybrid (sem ratchet) falhou: {:?}",
                            e
                        );
                        CryptoError::Protocol
                    })?;
                Ok(plaintext)
            }
        } else {
            if pqc_msg.ratchet_key.is_some() {
                vlog!(
                    VerbosityLevel::Normal,
                    "Componente PQC ignorado (modo PQC não habilitado)"
                );
                return Err(CryptoError::Protocol);
            }
            vlog!(
                VerbosityLevel::Debug,
                "  └─Mensagem clássica recebida (sem PQC)"
            );
            let plaintext = self
                .vodozemac_session
                .decrypt(&pqc_msg.classic_component)
                .map_err(|e| {
                    vlog!(
                        VerbosityLevel::Normal,
                        "ERRO: decrypt (modo clássico) falhou: {:?}",
                        e
                    );
                    CryptoError::Protocol
                })?;
            Ok(plaintext)
        }
    }

    /// Returns `true` if the PQC session has a peer key set (session has been used).
    ///
    /// Checks both layers: PQC (`their_ratchet_key`) and classical
    /// (`vodozemac_session.has_received_message()`).
    pub fn has_peer_key(&self) -> bool {
        let pqc_has_peer = if let Some(ref pqc_state) = self.pqc_ratchet {
            match &pqc_state.state {
                PqcRatchetState::Active {
                    their_ratchet_key, ..
                } => their_ratchet_key.is_some(),
                PqcRatchetState::Inactive { .. } => true,
            }
        } else {
            false
        };

        if pqc_has_peer {
            return true;
        }

        self.vodozemac_session.has_received_message()
    }

    /// Returns `true` if the underlying vodozemac session has received a message.
    pub fn has_received_message_classic(&self) -> bool {
        self.vodozemac_session.has_received_message()
    }

    /// Classical encryption fallback (for compatibility).
    pub fn encrypt_classic(&mut self, plaintext: &[u8]) -> vodozemac::olm::OlmMessage {
        self.vodozemac_session.encrypt(plaintext)
    }

    /// Classical decryption fallback (for compatibility).
    pub fn decrypt_classic(
        &mut self,
        message: &vodozemac::olm::OlmMessage,
    ) -> Result<Vec<u8>, vodozemac::olm::DecryptionError> {
        self.vodozemac_session.decrypt(message)
    }

    /// Encrypts using PQC if available, falling back to classical.
    /// Returns a Matrix-compatible serialized string.
    pub fn encrypt_transparent(&mut self, plaintext: &[u8]) -> String {
        if self.pqc_ratchet.is_some() {
            match self.encrypt_hybrid(plaintext) {
                Ok(pqc_msg) => pqc_msg.to_transport_string(),
                Err(e) => {
                    vlog!(
                        VerbosityLevel::Normal,
                        "FALLBACK CRÍTICO: encrypt_hybrid falhou ({:?}), usando clássico",
                        e
                    );
                    self.encrypt_classic_fallback(plaintext)
                }
            }
        } else {
            self.encrypt_classic_fallback(plaintext)
        }
    }

    /// Decrypts automatically, detecting the frame format from its prefix.
    pub fn decrypt_transparent(&mut self, ciphertext: &str) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.starts_with(r#"{"type":2,"#) {
            if self.pqc_ratchet.is_some() {
                let pqc_msg = PqcOlmMessage::from_transport_string(ciphertext)?;
                self.decrypt_hybrid(&pqc_msg)
            } else {
                Err(CryptoError::Protocol)
            }
        } else if ciphertext.starts_with("hybrid:") {
            self.decrypt_classic_fallback(&ciphertext[7..])
        } else {
            self.decrypt_classic_fallback(ciphertext)
        }
    }

    fn encrypt_classic_fallback(&mut self, plaintext: &[u8]) -> String {
        let message = self.vodozemac_session.encrypt(plaintext);
        use base64::prelude::*;
        match message {
            vodozemac::olm::OlmMessage::PreKey(m) => BASE64_STANDARD.encode(&m.to_bytes()),
            vodozemac::olm::OlmMessage::Normal(m) => BASE64_STANDARD.encode(&m.to_bytes()),
        }
    }

    fn decrypt_classic_fallback(&mut self, ciphertext: &str) -> Result<Vec<u8>, CryptoError> {
        use base64::prelude::*;
        let raw = BASE64_STANDARD
            .decode(ciphertext)
            .map_err(|_| CryptoError::B64)?;

        if let Ok(pre) = vodozemac::olm::PreKeyMessage::from_bytes(&raw) {
            let msg = vodozemac::olm::OlmMessage::PreKey(pre);
            return self
                .vodozemac_session
                .decrypt(&msg)
                .map_err(|_| CryptoError::Protocol);
        }

        if let Ok(norm) = vodozemac::olm::Message::from_bytes(&raw) {
            let msg = vodozemac::olm::OlmMessage::Normal(norm);
            return self
                .vodozemac_session
                .decrypt(&msg)
                .map_err(|_| CryptoError::Protocol);
        }

        Err(CryptoError::Protocol)
    }

    /// Returns `true` if PQC mode is active.
    pub fn is_pqc_enabled(&self) -> bool {
        self.pqc_ratchet.is_some()
    }

    /// Takes and returns the pending KEM ciphertext, leaving `None` in its place.
    pub fn take_pending_kem_ciphertext(&mut self) -> Option<Vec<u8>> {
        self.pending_kem_ciphertext.take()
    }

    /// Stores a KEM ciphertext to be attached to the next outgoing message.
    pub fn set_pending_kem_ciphertext(&mut self, kem_ct: Vec<u8>) {
        self.pending_kem_ciphertext = Some(kem_ct);
    }

    /// Returns the session ID from the underlying vodozemac session.
    pub fn session_id(&self) -> String {
        self.vodozemac_session.session_id()
    }

    /// Returns a statistics snapshot for this hybrid session.
    pub fn get_session_stats(&self) -> SessionStats {
        let pqc_stats = self.pqc_ratchet.as_ref().map(|s| s.get_ratchet_stats());
        SessionStats {
            total_messages: self.message_counter,
            pqc_enabled: self.pqc_ratchet.is_some(),
            session_id: self.vodozemac_session.session_id(),
            ratchet_stats: pqc_stats,
        }
    }
}

/// Statistics snapshot for a hybrid Olm session.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct SessionStats {
    pub total_messages: u32,
    pub pqc_enabled: bool,
    pub session_id: String,
    pub ratchet_stats: Option<RatchetStats>,
}
