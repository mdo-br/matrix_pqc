// HybridOlmSession: orquestrador vodozemac + Double Ratchet PQC

use crate::core::crypto::{CryptoError, KemAlgorithm};
use vodozemac::olm::Session as VodoSession;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::keys::{PqcRatchetKeyPair, PqcRatchetPublicKey};
use super::message::PqcOlmMessage;
use super::state::{PqcDoubleRatchetState, PqcRatchetState, RatchetStats};

/// Sessão Olm híbrida (orquestrador vodozemac + Double Ratchet PQC)
///
/// Combina sessão vodozemac clássica (base) com Double Ratchet PQC (extensão)
/// para fornecer segurança híbrida pós-quântica mantendo compatibilidade Matrix.
///
/// # Arquitetura em Camadas
///
/// **Camada Base (vodozemac_session)**:
/// - Double Ratchet clássico: X25519 ECDH
/// - Criptografia: AES-256-CBC + HMAC-SHA-256
/// - Formato: PreKeyMessage (primeira) ou Normal Message (subsequentes)
///
/// **Camada PQC (pqc_ratchet)**:
/// - Double Ratchet híbrido: X25519 + Kyber KEM em paralelo
/// - Derivação: HKDF-SHA-256 combina segredos DH + KEM → root_key + chain_key
/// - Estados: Active (enviando) ↔ Inactive (aguardando enviar)
///
/// **Camada de Mensagem**:
/// - Formato JSON: `{"type":2,"body":"base64"}` para mensagens PQC
/// - Detecção: Prefixo JSON identifica PQC, Base64 puro identifica clássico
///
/// # Fluxo de Operação
///
/// **Inicialização**:
/// 1. `from_vodozemac(vodozemac_session)` → modo clássico
/// 2. `enable_pqc_mode()` (sender) ou `enable_pqc_mode_as_receiver()` (receiver)
///
/// **Criptografia** (`encrypt_hybrid`):
/// 1. Avanço ratchet PQC → determina simétrico ou assimétrico
/// 2. Vodozemac encrypt → classic_component
/// 3. Monta PqcOlmMessage + serializa JSON
///
/// **Descriptografia** (`decrypt_hybrid`):
/// 1. Deserializa PqcOlmMessage do JSON
/// 2. Compara ratchet_key → detecta mudança de direção
/// 3. Avança ratchet conforme necessário
/// 4. Vodozemac decrypt → plaintext
pub struct HybridOlmSession {
    /// Sessão vodozemac base — pública para compatibilidade direta
    pub vodozemac_session: VodoSession,
    /// Estado do Double Ratchet híbrido PQC
    pqc_ratchet: Option<PqcDoubleRatchetState>,
    /// Contador de mensagens processadas
    message_counter: u32,
    /// KEM ciphertext pendente de forced ratchet (para incluir na próxima mensagem)
    pending_kem_ciphertext: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl HybridOlmSession {
    /// Retorna referência à sessão vodozemac base
    pub fn get_vodozemac_session(&self) -> &VodoSession {
        &self.vodozemac_session
    }

    /// Cria sessão híbrida a partir de sessão vodozemac
    pub fn from_vodozemac(session: VodoSession) -> Self {
        Self {
            vodozemac_session: session,
            pqc_ratchet: None,
            message_counter: 0,
            pending_kem_ciphertext: None,
        }
    }

    /// Habilita modo PQC (Alice — primeiro a enviar)
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

    /// Habilita modo PQC como receptor (Bob — primeiro a receber)
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

    /// Versão de compatibilidade (usa Kyber1024)
    pub fn enable_pqc_mode_default(&mut self, initial_root_key: [u8; 32]) {
        self.enable_pqc_mode(initial_root_key, KemAlgorithm::Kyber1024);
    }

    /// Define chave pública do peer para PQC
    pub fn set_peer_pqc_key(&mut self, peer_key: PqcRatchetPublicKey) -> Result<(), CryptoError> {
        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            pqc_state.set_peer_ratchet_key(peer_key);
            Ok(())
        } else {
            Err(CryptoError::Protocol)
        }
    }

    /// Obtém nossas chaves ratchet públicas atuais
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

    /// Força avanço assimétrico do Double Ratchet PQC (para rotações Megolm)
    ///
    /// Executa KEM completo imediatamente e armazena o ciphertext em
    /// `pending_kem_ciphertext` para ser incluído na próxima mensagem enviada.
    /// Garante forward secrecy PQC na rotação de chaves Megolm.
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

    /// Criptografa mensagem com Double Ratchet híbrido
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

            // Padrão Matrix: SEMPRE incluir nossa ratchet key atual
            let our_current_ratchet_key = match &pqc_state.state {
                PqcRatchetState::Active {
                    our_ratchet_keys, ..
                }
                | PqcRatchetState::Inactive {
                    our_ratchet_keys, ..
                } => our_ratchet_keys.public_keys(),
            };

            pqc_msg = pqc_msg.with_pqc_ratchet(our_current_ratchet_key);

            // Prioridade: KEM ciphertext de forced ratchet sobre o do avanço normal
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

    /// Descriptografa mensagem com Double Ratchet híbrido
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
                // Retrocompatibilidade: mensagem sem ratchet_key
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

    /// Verifica se a sessão PQC tem peer_key definida (sessão já foi usada)
    ///
    /// Verifica AMBAS as camadas:
    /// - Camada PQC: their_ratchet_key (KEM peer key)
    /// - Camada clássica: vodozemac has_received_message (DH peer key)
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

    /// Verifica se a sessão vodozemac já recebeu mensagem do peer
    pub fn has_received_message_classic(&self) -> bool {
        self.vodozemac_session.has_received_message()
    }

    /// Criptografia clássica (fallback/compatibilidade)
    pub fn encrypt_classic(&mut self, plaintext: &[u8]) -> vodozemac::olm::OlmMessage {
        self.vodozemac_session.encrypt(plaintext)
    }

    /// Descriptografia clássica (fallback/compatibilidade)
    pub fn decrypt_classic(
        &mut self,
        message: &vodozemac::olm::OlmMessage,
    ) -> Result<Vec<u8>, vodozemac::olm::DecryptionError> {
        self.vodozemac_session.decrypt(message)
    }

    /// Criptografa de forma inteligente (PQC se disponível, senão clássico)
    /// Retorna string serializada compatível com Matrix
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

    /// Descriptografa de forma inteligente (detecta formato pelo prefixo)
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

    /// Verifica se modo PQC está ativo
    pub fn is_pqc_enabled(&self) -> bool {
        self.pqc_ratchet.is_some()
    }

    /// Obtém e remove o pending_kem_ciphertext
    pub fn take_pending_kem_ciphertext(&mut self) -> Option<Vec<u8>> {
        self.pending_kem_ciphertext.take()
    }

    /// Define o pending_kem_ciphertext
    pub fn set_pending_kem_ciphertext(&mut self, kem_ct: Vec<u8>) {
        self.pending_kem_ciphertext = Some(kem_ct);
    }

    /// Obtém ID da sessão
    pub fn session_id(&self) -> String {
        self.vodozemac_session.session_id()
    }

    /// Obtém estatísticas da sessão híbrida
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

/// Estatísticas da sessão híbrida
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct SessionStats {
    pub total_messages: u32,
    pub pqc_enabled: bool,
    pub session_id: String,
    pub ratchet_stats: Option<RatchetStats>,
}
