#![allow(unused_imports, dead_code)]

use anyhow::{Result, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::crypto::{CryptoProvider, OlmSessionHandle, MegolmOutbound};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::*;

#[allow(dead_code)]
impl MatrixRoom {
    /// Creates an outbound Olm session without pre-generating the PreKeyMessage.
    ///
    /// The PreKeyMessage is generated automatically on the first `encrypt()` call.
    ///
    /// # Returns
    /// A tuple `(OlmSessionHandle, Option<MatrixPqxdhInitMessage>)`.
    pub(crate) fn create_outbound_olm_session_only(&mut self, sender_id: &str, receiver_id: &str) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>)> {
        let _start_time = std::time::Instant::now();
        
        // Check whether the sender is active (for metric accounting).
        // Sessions are created eagerly (N×(N-1) for PQXDH), but only active senders are counted.
        let should_count = self.active_senders.contains(sender_id);
        
        // Obter chaves de identidade e PQXDH do receptor
        let (receiver_identity_keys, receiver_pqxdh_keys) = {
            let receiver = self.members.get(receiver_id)
                .context("Receptor não encontrado")?;
            let identity_keys = receiver.crypto.upload_identity_keys();
            let pqxdh_keys = receiver.crypto.export_pqxdh_public_keys();
            
            // Trackear tamanho das chaves de identidade (Curve25519 + Ed25519)
            let curve_size = B64.decode(&identity_keys.curve25519).map(|v| v.len()).unwrap_or(32);
            let ed_size = B64.decode(&identity_keys.ed25519).map(|v| v.len()).unwrap_or(32);
            
            // CONTABILIZAR APENAS SE SENDER ATIVO
            if should_count {
                // Legacy accounting (full bundle — kept for comparison).
                self.bandwidth_key_exchange += curve_size + ed_size;

                // Isolated primitives: Identity Keys.
                self.bandwidth_agreement_primitives_identity_keys += curve_size + ed_size;

                // Comparison 2: control plane (agreement is part of control).
                self.bandwidth_control_plane += curve_size + ed_size;
            }
            
            // If hybrid, add the PQXDH key sizes.
            if let Some(ref pqxdh) = pqxdh_keys {
                if should_count {
                    // Legacy: counts full bundle (DUPLICATES classical keys!).
                    let pqxdh_json_str = serde_json::to_string(pqxdh).unwrap_or_default();
                    self.bandwidth_key_exchange += pqxdh_json_str.len();
                }
                
                // Isolated primitives: Kyber-1024 public key.
                if let Some(kyber_prekey) = pqxdh.get("prekeys")
                    .and_then(|p| p.get("kyber1024")) {
                    let kyber_json = serde_json::to_string(kyber_prekey).unwrap_or_default();
                    
                    if should_count {
                        self.bandwidth_agreement_primitives_kyber1024 += kyber_json.len();
                        self.bandwidth_control_plane += kyber_json.len();
                    }
                }
            }
            
            (identity_keys, pqxdh_keys)
        };

        // Gerar chave one-time para o receptor
        let receiver_otks = {
            let receiver = self.members.get_mut(receiver_id)
                .context("Receptor não encontrado para OTK")?;
            let otks = receiver.crypto.generate_one_time_keys(1);
            receiver.crypto.mark_keys_published();
            otks
        };

        let otk_key = receiver_otks.get(0)
            .context("Nenhuma chave one-time disponível")?;

        // Trackear tamanho da One-Time Key
        let otk_size = B64.decode(&otk_key.curve25519).map(|v| v.len()).unwrap_or(32);
        
        // CONTABILIZAR APENAS SE SENDER ATIVO
        if should_count {
            self.bandwidth_key_exchange += otk_size;
            
            // PRIMITIVAS ISOLADAS: OTK
            self.bandwidth_agreement_primitives_otk += otk_size;
            self.bandwidth_control_plane += otk_size;
        }

        // Obter crypto do remetente
        let sender_crypto = &mut self.members.get_mut(sender_id)
            .context("Remetente não encontrado")?
            .crypto;

        // Create the Olm OUTBOUND session.
        let session_result = match sender_crypto {
            CryptoWrapper::Hybrid(crypto) => {
                if let Some(pqxdh_keys) = receiver_pqxdh_keys {
                    crypto.set_peer_public_keys(pqxdh_keys);
                }
                
                if let Some(ref kem_key) = receiver_identity_keys.kem_pub_opt {
                    crypto.set_hybrid_kem_peer_pks(&[kem_key.clone()]);
                }
                
                crypto.create_outbound_session(
                    &receiver_identity_keys.curve25519,
                    &otk_key.curve25519
                )
            },
            CryptoWrapper::Classical(crypto) => {
                crypto.create_outbound_session(
                    &receiver_identity_keys.curve25519,
                    &otk_key.curve25519
                )
            }
        };

        let (session, init_message_opt) = session_result
            .map_err(|e| anyhow::anyhow!("Erro ao criar sessão Olm outbound: {:?}", e))?;

        // ============================================================================
        // REAL AGREEMENT MEASUREMENT: Identity Keys Bundle (serialised JSON)
        // ============================================================================
        // In Matrix, Agreement = uploading/downloading the Identity Keys Bundle from the server.
        // We measure the actual size of the full JSON bundle.
        if should_count {
            // Agreement = Identity Keys Bundle JSON.
            // Primitives already measured (identity, OTK, kyber1024).
            // Now compute the full bundle with real JSON overhead.

            let primitives_total = self.bandwidth_agreement_primitives_identity_keys
                                 + self.bandwidth_agreement_primitives_otk
                                 + self.bandwidth_agreement_primitives_kyber1024;

            // JSON structural overhead: object keys, commas, quotes, brackets.
            // Structure: {"curve25519":"...","ed25519":"...","one_time_keys":{...},"pqxdh":{...}}
            // Conservative estimate based on typical JSON structure: ~15% of primitives.
            let json_structural_overhead = (primitives_total as f64 * 0.15) as usize;
            
            let bundle_size = primitives_total + json_structural_overhead;
            
            // PROTOCOLO COMPLETO: Agreement = Bundle JSON
            self.bandwidth_agreement = bundle_size;
            
            // Calcular overhead JSON
            let primitives_total = self.bandwidth_agreement_primitives_identity_keys
                                 + self.bandwidth_agreement_primitives_otk
                                 + self.bandwidth_agreement_primitives_kyber1024;
            
            let json_overhead = if bundle_size > primitives_total {
                bundle_size - primitives_total
            } else {
                0
            };
            
            self.bandwidth_agreement_primitives_prekey_overhead = json_overhead;
            
            // Separar Classical vs PQC proporcionalmente
            let classical_primitives = self.bandwidth_agreement_primitives_identity_keys
                                     + self.bandwidth_agreement_primitives_otk;
            let pqc_primitives = self.bandwidth_agreement_primitives_kyber1024;
            
            if primitives_total > 0 {
                let classical_ratio = classical_primitives as f64 / primitives_total as f64;
                let pqc_ratio = pqc_primitives as f64 / primitives_total as f64;
                
                self.bandwidth_agreement_classical = classical_primitives + 
                    (json_overhead as f64 * classical_ratio) as usize;
                self.bandwidth_agreement_pqc = pqc_primitives +
                    (json_overhead as f64 * pqc_ratio) as usize;
            }
            
            vlog!(VerbosityLevel::Normal,
                  "     [AGREEMENT] Bundle: {} bytes (primitives={}, JSON overhead={})",
                  bundle_size, primitives_total, json_overhead);
        }

        // CONTABILIZAR INIT_MESSAGE (PQXDH additional overhead — sender→receiver transmission).
        if let Some(ref init_msg) = init_message_opt {
            if should_count {
                let init_msg_json = serde_json::to_string(init_msg).unwrap_or_default();
                let init_msg_size = init_msg_json.len();

                // Isolated primitives: init message already included in Kyber-1024.
                // Do NOT add again to avoid double-counting.

                self.bandwidth_control_plane += init_msg_size;

                // Legacy: also account for compatibility.
                self.bandwidth_key_exchange += init_msg_size;

                vlog!(VerbosityLevel::Debug, "     - Init message PQXDH: {} bytes (sender→receiver)", init_msg_size);
            }
        }

        // NOTE: Agreement time is measured GLOBALLY in create_sessions(),
        // not here (partial measurement would be inaccurate).

        Ok((session, init_message_opt))
    }

    /// Does NOT create an inbound session eagerly — waits for a PreKeyMessage.
    ///
    /// In the official vodozemac architecture, inbound sessions can ONLY be created
    /// upon receiving a PreKeyMessage via `create_inbound_session()`. There is no way
    /// to create one pre-emptively.
    ///
    /// Solution: leave `inbound = None` in `OlmSessionPair` until the first message
    /// arrives. That first message will be a PreKeyMessage and will create the inbound
    /// session automatically.
    ///
    /// This function exists for documentation purposes only — it must not be called.
    #[allow(dead_code)]
    fn create_inbound_olm_session_only(&mut self, _receiver_id: &str, _sender_id: &str) -> Result<OlmSessionHandle> {
        // Return an error indicating this function must not be used.
        Err(anyhow::anyhow!(
            "ERRO DE ARQUITETURA: Inbound sessions só podem ser criadas ao receber PreKeyMessage. \
             Use decrypt_megolm_key_via_olm_multi_sender() que criará automaticamente."
        ))
    }

    /// WARM-UP: Establishes `peer_key` in Olm sessions via test message exchange.
    ///
    /// # Motivation
    /// To measure the PQC overhead of forced ratchet during rotations, Olm sessions
    /// must have `their_ratchet_key` (peer_key) set. This only happens when the
    /// RECEIVER sends a message BACK to the sender.
    ///
    /// # Strategy
    /// For each existing outbound Olm session (already created for active senders):
    /// 1. Sender → Receiver: send a test message (establishes inbound on receiver).
    /// 2. Receiver → Sender: send a reply (establishes peer_key on sender's outbound).
    ///
    /// # Cost
    /// - Setup: 2 × N Olm messages per sender (round-trip).
    /// - Rotation: enables correct measurement of the forced ratchet KEM.
    ///
    /// # When to use
    /// Only in Hybrid mode for FS/PCS studies with PQC rotation.
    pub fn warmup_olm_sessions_for_pqc(&mut self) -> Result<()> {
        vlog!(VerbosityLevel::Verbose, "   - [WARM-UP PQC] Trocando mensagens Olm para estabelecer peer_key...");
        
        let test_message = b"warmup"; // minimal message
        let mut exchanges = 0;

        // Collect all sessions that need warm-up.
        let mut sessions_to_warmup: Vec<(String, String)> = Vec::new();
        
        for (member_id, member) in &self.members {
            for (peer_id, olm_pair) in &member.olm_sessions {
                if olm_pair.has_outbound() {
                    sessions_to_warmup.push((member_id.clone(), peer_id.clone()));
                }
            }
        }
        
        vlog!(VerbosityLevel::Debug, "   - {} sessões Olm outbound encontradas para warm-up", sessions_to_warmup.len());
        
        // For each outbound session:
        // 1. Sender encrypts and sends to receiver.
        // 2. Receiver decrypts (creates inbound if needed).
        // 3. Receiver encrypts a reply back to sender.
        // 4. Sender decrypts reply (establishes peer_key on the outbound!).
        for (sender_id, receiver_id) in &sessions_to_warmup {
            //  ═══════════════════════════════════════════════════════════════
            // STEP 1: Sender → Receiver (establishes inbound on receiver).
            // ═══════════════════════════════════════════════════════════════
            let encrypted_forward = {
                let sender = self.members.get_mut(sender_id)
                    .context("Sender não encontrado no warm-up")?;
                let olm_pair = sender.olm_sessions.get_mut(receiver_id)
                    .context("Par Olm não encontrado no warm-up")?;
                let outbound = olm_pair.outbound.as_mut()
                    .context("Sessão Olm outbound não existe no warm-up")?;
                
                sender.crypto.olm_encrypt(outbound, test_message)
            };
            
            // Receiver processa mensagem forward
            {
                let sender_identity = {
                    let sender = self.members.get(sender_id)
                        .context("Sender não encontrado ao obter identity")?;
                    sender.crypto.upload_identity_keys().curve25519
                };
                
                let receiver = self.members.get_mut(receiver_id)
                    .context("Receiver não encontrado no warm-up")?;
                let olm_pair = receiver.olm_sessions.entry(sender_id.clone())
                    .or_insert_with(OlmSessionPair::new);
                
                // Create inbound if it does not exist yet.
                if olm_pair.inbound.is_none() {
                    match receiver.crypto.create_inbound_session(&sender_identity, &encrypted_forward) {
                        Ok((inbound_session, _)) => {
                            olm_pair.inbound = Some(inbound_session);
                            vlog!(VerbosityLevel::Debug, "      └─ Inbound criada: {} <- {}", receiver_id, sender_id);
                        }
                        Err(e) => {
                            vlog!(VerbosityLevel::Debug, "      └─ Erro ao criar inbound: {:?}", e);
                            continue;
                        }
                    }
                } else {
                    // Decrypt mensagem normal
                    let inbound = olm_pair.inbound.as_mut()
                        .context("Inbound não existe")?;
                    let _ = receiver.crypto.olm_decrypt(inbound, &encrypted_forward)?;
                }
            }
            
            // ═══════════════════════════════════════════════════════════════
            // STEP 2: Receiver → Sender (establishes peer_key on sender's outbound).
            // ═══════════════════════════════════════════════════════════════

            // Receiver needs an outbound session back to sender; create one if missing.
            let encrypted_response = {
                // Verificar/criar outbound do receiver para sender
                let needs_outbound = {
                    let receiver = self.members.get(receiver_id)
                        .context("Receiver não encontrado")?;
                    receiver.olm_sessions.get(sender_id)
                        .map(|pair| !pair.has_outbound())
                        .unwrap_or(true)
                };
                
                if needs_outbound {
                    let (outbound_session, init_msg_opt) = 
                        self.create_outbound_olm_session_only(receiver_id, sender_id)?;
                    
                    if let Some(init_msg) = init_msg_opt {
                        if let Some(sender) = self.members.get_mut(sender_id) {
                            sender.crypto.set_pqxdh_init_message(init_msg);
                        }
                    }
                    
                    if let Some(receiver) = self.members.get_mut(receiver_id) {
                        let pair = receiver.olm_sessions.entry(sender_id.clone())
                            .or_insert_with(OlmSessionPair::new);
                        pair.outbound = Some(outbound_session);
                    }
                }
                
                // Agora encrypta resposta
                let receiver = self.members.get_mut(receiver_id)
                    .context("Receiver não encontrado")?;
                let olm_pair = receiver.olm_sessions.get_mut(sender_id)
                    .context("Par Olm não encontrado")?;
                let outbound = olm_pair.outbound.as_mut()
                    .context("Outbound não existe")?;
                
                receiver.crypto.olm_encrypt(outbound, test_message)
            };
            
            // Sender processes the response (creates inbound session if needed).
            {
                let receiver_identity = {
                    let receiver = self.members.get(receiver_id)
                        .context("Receiver não encontrado ao obter identity")?;
                    receiver.crypto.upload_identity_keys().curve25519
                };
                
                let sender = self.members.get_mut(sender_id)
                    .context("Sender não encontrado")?;
                let olm_pair = sender.olm_sessions.entry(receiver_id.clone())
                    .or_insert_with(OlmSessionPair::new);
                
                // Create inbound if it does not exist yet.
                if olm_pair.inbound.is_none() {
                    match sender.crypto.create_inbound_session(&receiver_identity, &encrypted_response) {
                        Ok((inbound_session, _)) => {
                            olm_pair.inbound = Some(inbound_session);
                            vlog!(VerbosityLevel::Debug, "      └─ Inbound criada: {} <- {} (resposta)", sender_id, receiver_id);
                        }
                        Err(e) => {
                            vlog!(VerbosityLevel::Debug, "      └─ Erro ao criar inbound: {:?}", e);
                            continue;
                        }
                    }
                } else {
                    // Decrypt mensagem normal
                    let inbound = olm_pair.inbound.as_mut()
                        .context("Inbound não existe")?;
                    let _ = sender.crypto.olm_decrypt(inbound, &encrypted_response)?;
                }
            }
            
            // ═══════════════════════════════════════════════════════════════
            // STEP 3: Sender → Receiver AGAIN (establishes peer_key on outbound!).
            // ═══════════════════════════════════════════════════════════════
            // CRITICAL: In the Olm Double Ratchet protocol, `their_ratchet_key` on the
            // outbound is only populated when we send a SECOND message AFTER receiving
            // the peer's reply. The first message uses the PreKey; the reply establishes
            // the inbound; only the third message causes the outbound to have
            // `their_ratchet_key` available.
            {
                let sender = self.members.get_mut(sender_id)
                    .context("Sender não encontrado")?;
                let olm_pair = sender.olm_sessions.get_mut(receiver_id)
                    .context("Par Olm não encontrado")?;
                let outbound = olm_pair.outbound.as_mut()
                    .context("Outbound não existe")?;
                
                // Verificar has_peer_key ANTES da terceira mensagem
                let has_peer_before = outbound.has_peer_key();
                vlog!(VerbosityLevel::Debug, "      └─ peer_key ANTES 3ª msg: {} -> {} = {}", 
                     sender_id, receiver_id, has_peer_before);
                
                // This encrypt call causes the outbound to process their_ratchet_key.
                let _encrypted_third = sender.crypto.olm_encrypt(outbound, test_message);
                
                // Verificar has_peer_key DEPOIS da terceira mensagem
                let has_peer_after = outbound.has_peer_key();
                vlog!(VerbosityLevel::Debug, "      └─ peer_key DEPOIS 3ª msg: {} -> {} = {}", 
                     sender_id, receiver_id, has_peer_after);
                
                if has_peer_after {
                    vlog!(VerbosityLevel::Debug, "      └─  peer_key CONFIRMADO: {} -> {}", sender_id, receiver_id);
                } else {
                    vlog!(VerbosityLevel::Debug, "      └─  peer_key NÃO estabelecido: {} -> {}", sender_id, receiver_id);
                }
            }
            
            exchanges += 1;
        }
        
        vlog!(VerbosityLevel::Verbose, "   -  Warm-up PQC concluído: {} trocas bidirecionais", exchanges);
        vlog!(VerbosityLevel::Verbose, "   -  peer_key estabelecido em {} sessões Olm outbound", exchanges);
        
        Ok(())
    }

    /// Creates Megolm sessions for all members (each member may send).
    /// If `active_senders` is empty, sessions are created for ALL members (full multi-sender mode).
    pub fn create_sessions_for_senders(&mut self, active_senders: &[String]) -> Result<()> {
        let sender_list = if active_senders.is_empty() {
            self.members.keys().cloned().collect()
        } else {
            active_senders.to_vec()
        };
        
        vlog!(VerbosityLevel::Verbose, "   - Criando sessões Megolm para {} sender(s)...", sender_list.len());
        
        // Register active senders so only their metrics are counted.
        // Olm sessions will be created eagerly (N×(N-1) for PQXDH), but only
        // those belonging to active senders are measured.
        self.active_senders.clear();
        for sender in &sender_list {
            self.active_senders.insert(sender.clone());
        }
        
        // Ativar flag de setup para rastrear largura de banda corretamente
        self.in_setup_phase = true;

        // ========================================================================
        // TIMING: Start global timer for Agreement + Initial Distribution.
        // ========================================================================
        let start_time_total = std::time::Instant::now();
        let start_time_agreement = std::time::Instant::now();
        
        let member_ids: Vec<String> = self.members.keys().cloned().collect();
        
        // Alignment with real Matrix (ToDeviceRequest):
        // each sender creates 1 batch with N-1 encrypted keys and "sends" it as 1 operation,
        // simulating ToDeviceRequest (1 HTTP POST with all keys)
        // instead of the previous P2P model (N-1 individual sends per sender).

        // Only active senders create outbound sessions.
        // This reflects the real user experience — each user only pays for their own sessions.
        for sender_id in &sender_list {
            // ========================================================================
            // PHASE 1: AGREEMENT — ensure Olm sessions exist (PQXDH/3DH handshake).
            // ========================================================================
            for receiver_id in &member_ids {
                if sender_id != receiver_id {
                    // Create Olm sessions (agreement phase).
                    self.ensure_olm_session(sender_id, receiver_id)?;
                }
            }
        }
        
        // ========================================================================
        // TIMING: Agreement complete (all Olm sessions established).
        // ========================================================================
        let agreement_time = start_time_agreement.elapsed().as_secs_f64() * 1000.0;
        self.time_agreement_ms = agreement_time;
        vlog!(VerbosityLevel::Normal, "   [AGREEMENT] Todas sessões Olm estabelecidas em {:.2}ms", agreement_time);
        
        // ========================================================================
        // PHASE 2: INITIAL DISTRIBUTION — send Megolm keys over Olm.
        // ========================================================================
        let start_time_initial_dist = std::time::Instant::now();
        
        for sender_id in &sender_list {
            // Create an outbound Megolm session for this sender.
            let sender = self.members.get_mut(sender_id)
                .context("Sender não encontrado")?;
            
            let megolm_outbound = sender.crypto.megolm_create_outbound();
            let session_key = sender.crypto.megolm_export_inbound(&megolm_outbound);

            // BATCH: Coletar todas as chaves cifradas para este sender
            let mut batch_encrypted_keys: Vec<(String, Vec<u8>)> = Vec::new();
            
            for receiver_id in &member_ids {
                if sender_id != receiver_id {
                    // Encrypt the Megolm key for this receiver (via the already-established Olm session).
                    match self.encrypt_megolm_key_via_olm_multi_sender(sender_id, &session_key, receiver_id) {
                        Ok(encrypted_key) => {
                            batch_encrypted_keys.push((receiver_id.clone(), encrypted_key));
                        }
                        Err(e) => {
                            vlog!(VerbosityLevel::Debug, "       -  Erro ao criptografar chave de {} para {}: {}", sender_id, receiver_id, e);
                        }
                    }
                }
            }

            // "SEND": Simulates 1 ToDeviceRequest with all N-1 encrypted keys.
            // In real Matrix: 1 HTTP POST to the server with a batch of keys.
            // Here: bandwidth was already accounted for in encrypt_megolm_key_via_olm_multi_sender
            // (no need to sum again — each encrypt already increments bandwidth_initial_distribution).

            // RECEIVE: Cada receiver descriptografa sua chave
            for (receiver_id, encrypted_key) in batch_encrypted_keys {
                match self.decrypt_megolm_key_via_olm_multi_sender(&encrypted_key, &receiver_id, sender_id) {
                    Ok(decrypted_key) => {
                        if let Some(receiver) = self.members.get_mut(&receiver_id) {
                            let megolm_inbound = receiver.crypto.megolm_import_inbound(&decrypted_key);
                            receiver.megolm_inbound = Some(megolm_inbound);
                        }
                    }
                    Err(e) => {
                        vlog!(VerbosityLevel::Debug, "       -  Erro ao descriptografar chave de {} para {}: {}", sender_id, receiver_id, e);
                    }
                }
            }

            // Store the outbound session.
            self.sender_sessions.insert(sender_id.clone(), megolm_outbound);
            self.message_count_per_sender.insert(sender_id.clone(), 0);
        }
        
        // ========================================================================
        // TIMING: Initial Distribution complete.
        // ========================================================================
        let initial_dist_time = start_time_initial_dist.elapsed().as_secs_f64() * 1000.0;
        self.time_initial_distribution_ms = initial_dist_time;
        
        let total_time = start_time_total.elapsed().as_secs_f64() * 1000.0;
        vlog!(VerbosityLevel::Minimal, "   - Sessões criadas: {} senders em {:.2}ms (Agreement: {:.2}ms, Initial Dist: {:.2}ms)", 
             sender_list.len(), total_time, agreement_time, initial_dist_time);

        // Desativar flag de setup
        self.in_setup_phase = false;

        Ok(())
    }
    
    /// Creates Megolm sessions for all members (compatibility — full multi-sender mode).
    pub fn create_sessions(&mut self) -> Result<()> {
        self.create_sessions_for_senders(&[])
    }

    /// Bidirectional warm-up: establishes `peer_key` in all Olm sessions.
    ///
    /// GOAL: Prepare Olm sessions so `forced_ratchet` works correctly.
    ///
    /// PROBLEM SOLVED:
    /// - Freshly created Olm sessions are "lazy" (no peer_key set).
    /// - `forced_ratchet_advance()` needs peer_key to perform the KEM.
    /// - Megolm key distribution is UNIDIRECTIONAL (does not set peer_key).
    /// - vodozemac only marks `has_received_message()` on INBOUND sessions (receivers).
    ///
    /// SOLUTION (bidirectional warm-up):
    /// - Each pair (A, B) exchanges dummy messages in BOTH directions:
    ///   1. A → B: sends "warmup_A_to_B".
    ///   2. B decrypts → peer_key set on B's INBOUND session (receives from A).
    ///   3. B → A: sends "warmup_B_to_A".
    ///   4. A decrypts → peer_key set on A's INBOUND session (receives from B).
    /// - After warm-up: all INBOUND sessions have peer_key set.
    /// - `forced_ratchet` checks peer_key on the receiver's INBOUND before executing the KEM.
    ///
    /// TIMING: Must be called AFTER `create_sessions_for_senders()` and BEFORE the first rotation.
    pub fn warmup_olm_sessions_bidirectional(&mut self) -> Result<()> {
        vlog!(VerbosityLevel::Normal, "   - [WARMUP] Estabelecendo peer_key bidirecionalmente em todas as sessões Olm");
        
        let mut warmup_messages: Vec<(String, String, Vec<u8>)> = Vec::new(); // (sender, receiver, encrypted)
        let mut warmup_sent = 0;
        let mut warmup_received = 0;
        
        // Phase 0: Collect (sender, receiver) pairs where an outbound session already exists.
        let mut session_pairs: Vec<(String, String)> = Vec::new();
        for (sender_id, sender) in self.members.iter() {
            for (receiver_id, olm_pair) in sender.olm_sessions.iter() {
                if sender_id != receiver_id && olm_pair.outbound.is_some() {
                    session_pairs.push((sender_id.clone(), receiver_id.clone()));
                }
            }
        }
        
        // Phase 1: Send dummy messages in every identified direction.
        for (sender_id, receiver_id) in session_pairs {
            let warmup_payload = format!("warmup_{}_{}", sender_id, receiver_id);
            
            match self.encrypt_simple_message(&sender_id, &receiver_id, warmup_payload.as_bytes()) {
                Ok(encrypted) => {
                    warmup_messages.push((sender_id.clone(), receiver_id.clone(), encrypted));
                    warmup_sent += 1;
                }
                Err(e) => {
                    vlog!(VerbosityLevel::Debug, "      └─ [WARMUP]  Erro ao enviar de {} para {}: {}", sender_id, receiver_id, e);
                }
            }
        }
        
        vlog!(VerbosityLevel::Debug, "      └─ [WARMUP] {} mensagens enviadas", warmup_sent);
        
        // Fase 2: Descriptografar (estabelece peer_key nas sessions inbound correspondentes)
        for (warmup_sender, warmup_receiver, encrypted) in warmup_messages {
            match self.decrypt_simple_message(&encrypted, &warmup_receiver, &warmup_sender) {
                Ok(_) => {
                    warmup_received += 1;
                }
                Err(e) => {
                    vlog!(VerbosityLevel::Debug, "      └─ [WARMUP]  Erro ao descriptografar de {} para {}: {}", warmup_sender, warmup_receiver, e);
                }
            }
        }
        
        vlog!(VerbosityLevel::Debug, "      └─ [WARMUP] {} mensagens recebidas", warmup_received);
        
        // Phase 3: Count how many outbound sessions have a peer_key established.
        // FIX: For session A→B, peer_key is established on B's INBOUND session (receiving from A).
        // We must check if B.inbound(A) has has_received_message() == true.
        let mut sessions_with_peer_key = 0;
        let mut sessions_total = 0;
        let mut sessions_pqc_peer = 0;
        let mut sessions_classic_peer = 0;
        
        for (sender_id, sender) in self.members.iter() {
            for (receiver_id, olm_pair) in sender.olm_sessions.iter() {
                if olm_pair.outbound.is_some() {
                    sessions_total += 1;
                    
                    // Check whether the RECEIVER has an INBOUND session from the SENDER with peer_key set.
                    let has_peer_key = if let Some(receiver) = self.members.get(receiver_id) {
                        if let Some(receiver_pair) = receiver.olm_sessions.get(sender_id) {
                            if let Some(ref inbound) = receiver_pair.inbound {
                                let has_classic = inbound.has_received_message_classic();
                                let has_pqc = inbound.has_peer_key(); // also checks the PQC layer.
                                
                                if has_classic {
                                    sessions_classic_peer += 1;
                                }
                                if has_pqc {
                                    sessions_pqc_peer += 1;
                                }
                                
                                has_classic || has_pqc
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    
                    if has_peer_key {
                        sessions_with_peer_key += 1;
                    }
                    
                    vlog!(VerbosityLevel::Debug, "      └─ [WARMUP] Sessão {} → {}: peer_key_inbound={}", 
                         sender_id, receiver_id, has_peer_key);
                }
            }
        }
        
        vlog!(VerbosityLevel::Normal, "      └─ [WARMUP] peer_key estabelecido em {}/{} sessões (Classic: {}, PQC: {})", 
             sessions_with_peer_key, sessions_total, sessions_classic_peer, sessions_pqc_peer);
        
        if sessions_with_peer_key < sessions_total {
            vlog!(VerbosityLevel::Normal, "      └─ [WARMUP]  {} sessões ainda sem peer_key no inbound do receiver", 
                 sessions_total - sessions_with_peer_key);
        }
        
        Ok(())
    }
    /// Criptografa mensagem simples via Olm (usado para warm-up bidirecional)
    fn encrypt_simple_message(&mut self, sender_id: &str, receiver_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sender = self.members.get_mut(sender_id)
            .context("Sender não encontrado")?;
        
        let olm_session_pair = sender.olm_sessions.get_mut(receiver_id)
            .context("Sessão Olm não encontrada")?;
        
        let olm_session = olm_session_pair.get_outbound_mut()
            .context("Sessão Olm outbound não encontrada")?;

        Ok(sender.crypto.olm_encrypt(olm_session, plaintext))
    }
    
    /// Descriptografa mensagem simples via Olm (usado para warm-up bidirecional)
    fn decrypt_simple_message(&mut self, encrypted: &[u8], receiver_id: &str, sender_id: &str) -> Result<Vec<u8>> {
        // Primeiro, obter as chaves de identidade do sender
        let sender_identity_keys = {
            let sender = self.members.get(sender_id)
                .context("Sender não encontrado")?;
            sender.crypto.upload_identity_keys()
        };

        let receiver = self.members.get_mut(receiver_id)
            .context("Receptor não encontrado")?;

        // Check whether an established Olm inbound session already exists.
        if let Some(existing_pair) = receiver.olm_sessions.get_mut(sender_id) {
            if let Some(inbound_session) = existing_pair.get_inbound_mut() {
                // Try to use the existing inbound session.
                match receiver.crypto.olm_decrypt(inbound_session, encrypted) {
                    Ok(decrypted_bytes) => {
                        return Ok(decrypted_bytes);
                    }
                    Err(e) => {
                        // Existing session failed — may be a new PreKeyMessage.
                        vlog!(VerbosityLevel::Debug, "      └─ [WARMUP] Sessão inbound existente falhou, tentando criar nova: {:?}", e);
                    }
                }
            }
        }

        // No inbound session found or it failed; create a new one from the PreKeyMessage.
        let (mut inbound_session, _) = receiver.crypto.create_inbound_session(&sender_identity_keys.curve25519, encrypted)?;
        let decrypted_bytes = receiver.crypto.olm_decrypt(&mut inbound_session, encrypted)?;

        // Store the newly created inbound session.
        receiver.olm_sessions
            .entry(sender_id.to_string())
            .or_insert_with(OlmSessionPair::new)
            .inbound = Some(inbound_session);

        Ok(decrypted_bytes)
    }
}
