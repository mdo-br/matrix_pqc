#![allow(unused_imports, dead_code)]

use anyhow::{Result, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::crypto::{CryptoProvider, OlmSessionHandle, MegolmOutbound};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::*;

#[allow(dead_code)]
impl MatrixRoom {
    /// Cria sessão Olm OUTBOUND sem gerar PreKeyMessage antecipadamente
    /// PreKeyMessage será gerada AUTOMATICAMENTE na primeira encrypt()
    /// 
    /// # Retorno
    /// Tupla (OlmSessionHandle, Option<MatrixPqxdhInitMessage>)
    pub(crate) fn create_outbound_olm_session_only(&mut self, sender_id: &str, receiver_id: &str) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>)> {
        let _start_time = std::time::Instant::now();
        
        // VERIFICAR SE SENDER ESTÁ ATIVO (para contabilizar métricas)
        // Sessões são criadas eagerly (N×(N-1) para PQXDH), mas só contamos as dos senders ativos
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
                // Contabilização LEGACY (bundle completo - mantido para comparação)
                self.bandwidth_key_exchange += curve_size + ed_size;
                
                // PRIMITIVAS ISOLADAS: Identity Keys
                self.bandwidth_agreement_primitives_identity_keys += curve_size + ed_size;
                
                // COMPARAÇÃO 2: CONTROLE (acordo é parte do controle)
                self.bandwidth_control_plane += curve_size + ed_size;
            }
            
            // Se híbrido, adicionar tamanho das chaves PQXDH
            if let Some(ref pqxdh) = pqxdh_keys {
                if should_count {
                    // LEGACY: Conta bundle completo (DUPLICA chaves clássicas!)
                    let pqxdh_json_str = serde_json::to_string(pqxdh).unwrap_or_default();
                    self.bandwidth_key_exchange += pqxdh_json_str.len();
                }
                
                // PRIMITIVAS ISOLADAS: Kyber-1024 public key
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

        // Criar sessão Olm OUTBOUND
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
        // MEDIÇÃO REAL DE AGREEMENT: Identity Keys Bundle (JSON serializado)
        // ============================================================================
        // No Matrix, Agreement = Upload/Download de Identity Keys Bundle no servidor
        // Medimos o tamanho REAL do bundle JSON completo
        
        if should_count {
            // Agreement = Identity Keys Bundle JSON
            // Já medimos as primitivas (identity, OTK, kyber1024)
            // Agora calculamos o bundle completo com overhead JSON REAL
            
            let primitives_total = self.bandwidth_agreement_primitives_identity_keys
                                 + self.bandwidth_agreement_primitives_otk
                                 + self.bandwidth_agreement_primitives_kyber1024;
            
            // Overhead JSON estrutural: chaves do objeto, vírgulas, aspas, colchetes
            // Estrutura: {"curve25519":"...","ed25519":"...","one_time_keys":{...},"pqxdh":{...}}
            // Estimativa conservadora baseada em estrutura JSON típica: ~15% das primitivas
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

        // CONTABILIZAR INIT_MESSAGE (overhead PQXDH adicional - transmissão sender→receiver)
        if let Some(ref init_msg) = init_message_opt {
            if should_count {
                // Serializar init_message para medir tamanho real
                let init_msg_json = serde_json::to_string(init_msg).unwrap_or_default();
                let init_msg_size = init_msg_json.len();
                
                // PRIMITIVAS ISOLADAS: Init message já incluída no Kyber-1024
                // (não adicionar novamente, evitar duplicação)
                
                self.bandwidth_control_plane += init_msg_size;
                
                // LEGACY: também contabilizar para compatibilidade
                self.bandwidth_key_exchange += init_msg_size;
                
                vlog!(VerbosityLevel::Debug, "     - Init message PQXDH: {} bytes (sender→receiver)", init_msg_size);
            }
        }

        // NOTA: Tempo de Agreement será medido GLOBALMENTE em create_sessions()
        // (não medir fragmentadamente aqui - seria parcial)

        Ok((session, init_message_opt))
    }

    /// NÃO CRIA sessão inbound antecipadamente - aguarda PreKeyMessage
    /// 
    /// IMPORTANTE: Na arquitetura oficial vodozemac, inbound sessions SÓ são criadas
    /// ao receber PreKeyMessage via create_inbound_session(). Não há como criar
    /// inbound session antecipadamente.
    /// 
    /// Solução: Deixar inbound = None no OlmSessionPair até receber primeira mensagem.
    /// A primeira mensagem será PreKeyMessage e irá criar a inbound session automaticamente.
    ///
    /// Esta função existe apenas para documentação - não deve ser chamada.
    #[allow(dead_code)]
    fn create_inbound_olm_session_only(&mut self, _receiver_id: &str, _sender_id: &str) -> Result<OlmSessionHandle> {
        // Retornar erro indicando que esta função não deve ser usada
        Err(anyhow::anyhow!(
            "ERRO DE ARQUITETURA: Inbound sessions só podem ser criadas ao receber PreKeyMessage. \
             Use decrypt_megolm_key_via_olm_multi_sender() que criará automaticamente."
        ))
    }

    /// WARM-UP: Estabelece peer_key em sessões Olm via troca de mensagens de teste
    /// 
    /// # Motivação
    /// Para medir overhead PQC do forced ratchet nas rotações, precisamos que as
    /// sessões Olm tenham `their_ratchet_key` (peer_key) estabelecido. Isso só
    /// acontece quando o RECEIVER envia uma mensagem DE VOLTA para o sender.
    /// 
    /// # Estratégia
    /// Para cada sessão Olm outbound existente (já criadas para senders ativos):
    /// 1. Sender → Receiver: Enviar mensagem de teste (estabelece inbound no receiver)
    /// 2. Receiver → Sender: Enviar resposta (estabelece peer_key no outbound do sender)
    /// 
    /// # Custo
    /// - Setup: 2 × N mensagens Olm por sender (ida + volta)
    /// - Rotação: Habilita medição correta do forced ratchet KEM
    /// 
    /// # Quando usar
    /// Apenas em modo Hybrid para estudos de FS/PCS com rotação PQC
    pub fn warmup_olm_sessions_for_pqc(&mut self) -> Result<()> {
        vlog!(VerbosityLevel::Verbose, "   - [WARM-UP PQC] Trocando mensagens Olm para estabelecer peer_key...");
        
        let test_message = b"warmup"; // Mensagem mínima
        let mut exchanges = 0;
        
        // Coletar todas as sessões que precisam de warm-up
        let mut sessions_to_warmup: Vec<(String, String)> = Vec::new();
        
        for (member_id, member) in &self.members {
            for (peer_id, olm_pair) in &member.olm_sessions {
                if olm_pair.has_outbound() {
                    sessions_to_warmup.push((member_id.clone(), peer_id.clone()));
                }
            }
        }
        
        vlog!(VerbosityLevel::Debug, "   - {} sessões Olm outbound encontradas para warm-up", sessions_to_warmup.len());
        
        // Para cada sessão outbound:
        // 1. Sender encrypta e envia mensagem para receiver
        // 2. Receiver decrypt (cria inbound se necessário)
        // 3. Receiver encrypta resposta de volta para sender  
        // 4. Sender decrypt resposta (estabelece peer_key no outbound!)
        
        for (sender_id, receiver_id) in &sessions_to_warmup {
            //  ═══════════════════════════════════════════════════════════════
            // PASSO 1: Sender → Receiver (estabelece inbound no receiver)
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
                
                // Criar inbound se não existe
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
            // PASSO 2: Receiver → Sender (estabelece peer_key no outbound do sender!)
            // ═══════════════════════════════════════════════════════════════
            
            // Receiver precisa ter sessão outbound de volta para sender
            // Se não existe, criar agora
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
            
            // Sender processa resposta (cria inbound se necessário)
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
                
                // Criar inbound se não existe
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
            // PASSO 3: Sender → Receiver NOVAMENTE (ESTABELECE peer_key no outbound!)
            // ═══════════════════════════════════════════════════════════════
            // CRÍTICO: No protocolo Olm Double Ratchet, their_ratchet_key só é
            // estabelecido no outbound quando enviamos uma SEGUNDA mensagem APÓS
            // ter recebido a resposta do peer. A primeira mensagem usa PreKey,
            // a resposta estabelece inbound, mas só a terceira mensagem faz o
            // outbound ter their_ratchet_key disponível.
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
                
                // Esta encrypt fará o outbound processar their_ratchet_key!
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

    /// Cria sessões Megolm para todos os membros (cada membro pode enviar)
    /// Cria sessões Megolm apenas para senders especificados
    /// Se active_senders estiver vazio, cria para TODOS os membros (modo multi-sender completo)
    pub fn create_sessions_for_senders(&mut self, active_senders: &[String]) -> Result<()> {
        let sender_list = if active_senders.is_empty() {
            self.members.keys().cloned().collect()
        } else {
            active_senders.to_vec()
        };
        
        vlog!(VerbosityLevel::Verbose, "   - Criando sessões Megolm para {} sender(s)...", sender_list.len());
        
        // REGISTRAR ACTIVE SENDERS: Para contabilizar apenas suas métricas
        // Sessões Olm serão criadas eagerly (N×(N-1) para PQXDH), mas só contamos
        // bandwidth/tempo das que pertencem aos senders ativos
        self.active_senders.clear();
        for sender in &sender_list {
            self.active_senders.insert(sender.clone());
        }
        
        // Ativar flag de setup para rastrear largura de banda corretamente
        self.in_setup_phase = true;

        // ========================================================================
        // TIMING: Iniciar cronômetro GLOBAL para Agreement + Initial Distribution
        // ========================================================================
        let start_time_total = std::time::Instant::now();
        let start_time_agreement = std::time::Instant::now();
        
        let member_ids: Vec<String> = self.members.keys().cloned().collect();
        
        // REFATORAÇÃO: Alinhamento com Matrix real (ToDeviceRequest)
        // Cada sender cria 1 batch com N-1 chaves cifradas e "envia" como 1 operação
        // Isso simula o comportamento do ToDeviceRequest (1 HTTP POST com todas as keys)
        // ao invés do modelo P2P anterior (N-1 sends individuais por sender)
        
        // IMPORTANTE: Apenas senders ativos criam sessões outbound
        // Isso reflete a experiência real do usuário - apenas paga overhead das suas próprias sessões
        for sender_id in &sender_list {
            // ========================================================================
            // FASE 1: AGREEMENT - Garantir sessões Olm existem (PQXDH/3DH handshake)
            // ========================================================================
            for receiver_id in &member_ids {
                if sender_id != receiver_id {
                    // Criar sessões Olm (Agreement phase)
                    self.ensure_olm_session(sender_id, receiver_id)?;
                }
            }
        }
        
        // ========================================================================
        // TIMING: Finalizar Agreement (TODAS as sessões Olm criadas)
        // ========================================================================
        let agreement_time = start_time_agreement.elapsed().as_secs_f64() * 1000.0;
        self.time_agreement_ms = agreement_time;
        vlog!(VerbosityLevel::Normal, "   [AGREEMENT] Todas sessões Olm estabelecidas em {:.2}ms", agreement_time);
        
        // ========================================================================
        // FASE 2: INITIAL DISTRIBUTION - Distribuir chaves Megolm via Olm
        // ========================================================================
        let start_time_initial_dist = std::time::Instant::now();
        
        for sender_id in &sender_list {
            // Criar sessão Megolm outbound para este sender
            let sender = self.members.get_mut(sender_id)
                .context("Sender não encontrado")?;
            
            let megolm_outbound = sender.crypto.megolm_create_outbound();
            let session_key = sender.crypto.megolm_export_inbound(&megolm_outbound);

            // BATCH: Coletar todas as chaves cifradas para este sender
            let mut batch_encrypted_keys: Vec<(String, Vec<u8>)> = Vec::new();
            
            for receiver_id in &member_ids {
                if sender_id != receiver_id {
                    // Criptografar chave Megolm para este receiver (via sessão Olm já criada)
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

            // "SEND": Simula 1 ToDeviceRequest com todas as N-1 chaves cifradas
            // No Matrix real: 1 HTTP POST ao servidor com batch de keys
            // Aqui: a bandwidth já foi contabilizada em encrypt_megolm_key_via_olm_multi_sender
            // (não precisamos somar novamente - cada encrypt já incrementa bandwidth_initial_distribution)

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

            // Armazenar sessão outbound
            self.sender_sessions.insert(sender_id.clone(), megolm_outbound);
            self.message_count_per_sender.insert(sender_id.clone(), 0);
        }
        
        // ========================================================================
        // TIMING: Finalizar Initial Distribution
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
    
    /// Cria sessões Megolm para todos os membros (compatibilidade - modo multi-sender completo)
    pub fn create_sessions(&mut self) -> Result<()> {
        self.create_sessions_for_senders(&[])
    }
    
    /// Warm-up bidirecional: Estabelece peer_key em todas as sessões Olm
    /// 
    /// OBJETIVO: Preparar sessões Olm para forced_ratchet funcionar
    /// 
    /// PROBLEMA RESOLVIDO:
    /// - Sessões Olm recém-criadas são "lazy" (sem peer_key estabelecido)
    /// - forced_ratchet_advance() precisa de peer_key para executar KEM
    /// - Distribuição de chaves Megolm é UNIDIRECIONAL (não estabelece peer_key)
    /// - vodozemac só marca has_received_message() em sessões INBOUND (que descriptografam)
    /// 
    /// SOLUÇÃO (Warm-up bidirecional):
    /// - Cada par (A, B) troca mensagens dummy em AMBAS as direções:
    ///   1. A → B: envia "warmup_A_to_B"
    ///   2. B descriptografa → peer_key estabelecido em sessão INBOUND de B (recebe de A)
    ///   3. B → A: envia "warmup_B_to_A"  
    ///   4. A descriptografa → peer_key estabelecido em sessão INBOUND de A (recebe de B)
    /// - Após warm-up: Todas sessões INBOUND têm peer_key estabelecido
    /// - forced_ratchet verifica peer_key no INBOUND do receiver antes de executar KEM
    /// 
    /// TIMING: Deve ser chamado APÓS create_sessions_for_senders() e ANTES da primeira rotação
    pub fn warmup_olm_sessions_bidirectional(&mut self) -> Result<()> {
        vlog!(VerbosityLevel::Normal, "   - [WARMUP] Estabelecendo peer_key bidirecionalmente em todas as sessões Olm");
        
        let mut warmup_messages: Vec<(String, String, Vec<u8>)> = Vec::new(); // (sender, receiver, encrypted)
        let mut warmup_sent = 0;
        let mut warmup_received = 0;
        
        // Fase 0: Coletar pares (sender, receiver) onde sessão outbound já existe
        let mut session_pairs: Vec<(String, String)> = Vec::new();
        for (sender_id, sender) in self.members.iter() {
            for (receiver_id, olm_pair) in sender.olm_sessions.iter() {
                if sender_id != receiver_id && olm_pair.outbound.is_some() {
                    session_pairs.push((sender_id.clone(), receiver_id.clone()));
                }
            }
        }
        
        // Fase 1: Enviar mensagens dummy em todas as direções identificadas
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
        
        // Fase 3: Verificar quantas sessões outbound têm peer_key estabelecido
        // CORREÇÃO: Para sessão A→B, peer_key é estabelecido na sessão INBOUND de B (que recebe de A)
        // Precisamos verificar se B.inbound(A) tem has_received_message() == true
        let mut sessions_with_peer_key = 0;
        let mut sessions_total = 0;
        let mut sessions_pqc_peer = 0;
        let mut sessions_classic_peer = 0;
        
        for (sender_id, sender) in self.members.iter() {
            for (receiver_id, olm_pair) in sender.olm_sessions.iter() {
                if olm_pair.outbound.is_some() {
                    sessions_total += 1;
                    
                    // Verificar se o RECEIVER tem sessão INBOUND do SENDER com peer_key
                    let has_peer_key = if let Some(receiver) = self.members.get(receiver_id) {
                        if let Some(receiver_pair) = receiver.olm_sessions.get(sender_id) {
                            if let Some(ref inbound) = receiver_pair.inbound {
                                let has_classic = inbound.has_received_message_classic();
                                let has_pqc = inbound.has_peer_key(); // verifica camada PQC também
                                
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

        // Verificar se já existe sessão Olm inbound estabelecida
        if let Some(existing_pair) = receiver.olm_sessions.get_mut(sender_id) {
            if let Some(inbound_session) = existing_pair.get_inbound_mut() {
                // Tentar usar sessão inbound existente
                match receiver.crypto.olm_decrypt(inbound_session, encrypted) {
                    Ok(decrypted_bytes) => {
                        return Ok(decrypted_bytes);
                    }
                    Err(e) => {
                        // Falha na sessão existente - pode ser PreKeyMessage nova
                        vlog!(VerbosityLevel::Debug, "      └─ [WARMUP] Sessão inbound existente falhou, tentando criar nova: {:?}", e);
                    }
                }
            }
        }

        // Se não tem sessão inbound ou falhou, criar nova a partir de PreKeyMessage
        let (mut inbound_session, _) = receiver.crypto.create_inbound_session(&sender_identity_keys.curve25519, encrypted)?;
        let decrypted_bytes = receiver.crypto.olm_decrypt(&mut inbound_session, encrypted)?;

        // Armazenar sessão inbound criada
        receiver.olm_sessions
            .entry(sender_id.to_string())
            .or_insert_with(OlmSessionPair::new)
            .inbound = Some(inbound_session);

        Ok(decrypted_bytes)
    }
}
