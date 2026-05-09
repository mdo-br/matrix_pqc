#![allow(unused_imports, dead_code)]

use anyhow::{Result, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::crypto::{CryptoProvider, OlmSessionHandle, MegolmOutbound};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::*;

#[allow(dead_code)]
impl MatrixRoom {
    /// Rotaciona APENAS sessões Megolm dos senders ativos, preservando sessões Olm existentes
    /// Método otimizado conforme recomendação para reduzir overhead de rotação
    pub(crate) fn rotate_megolm_only(&mut self, reason: String) -> Result<()> {
        let start_time = std::time::Instant::now();
        vlog!(VerbosityLevel::Verbose, "   - Rotacionando APENAS sessões Megolm (razão: {}) - preservando Olm", reason);
        
        // MARCAR INÍCIO DA FASE DE ROTAÇÃO (para contagem consistente de bandwidth)
        self.in_rotation_phase = true;
        vlog!(VerbosityLevel::Normal, "   [ROTATION_PHASE] INICIADA (rotation_count={})", self.rotation_count);
        
        // Arquivar estatísticas da sessão atual e determinar se é uma rotação real
        let is_rotation = !self.sender_sessions.is_empty();
        
        if is_rotation {
            self.session_history.push(std::mem::take(&mut self.current_session_stats));
            self.rotation_count += 1;
        }

        // Resetar contadores para nova sessão
        self.message_count = 0;
        self.message_count_per_sender.clear();
        self.session_start_time = std::time::Instant::now();

        // ============================================================================
        // MULTI-SENDER ROTATION: Redistribuir chaves Megolm de TODOS os senders ativos
        // ============================================================================
        // No Matrix real, cada sender mantém sua própria sessão Megolm outbound.
        // Durante rotação, CADA sender:
        // 1. Cria nova sessão Megolm outbound
        // 2. Distribui a nova chave via Olm para todos os outros membros
        // 
        // Isso cria tráfego Olm BIDIRECIONAL natural:
        // - Sender A → receivers (B, C, D, ...)
        // - Sender B → receivers (A, C, D, ...)
        // - Sender C → receivers (A, B, D, ...)
        // 
        // Resultado: Cada par de dispositivos troca mensagens Olm, estabelecendo peer_key
        //
        // IMPORTANTE - Comportamento de peer_key:
        // - Primeira rotação: Sessões Olm outbound ainda "lazy" (sem peer_key)
        //   porque acabaram de ser criadas e nunca receberam mensagens de volta
        // - Segunda rotação em diante: peer_key estabelecido naturalmente
        //   porque cada sender já recebeu distribuições de outros senders
        //   (ex: A recebeu de B, então sessão outbound A→B agora "conhece" B)
        // 
        // Isto reflete o comportamento real do Matrix onde peer_key é estabelecido
        // gradualmente através do uso contínuo das sessões Olm.
        
        let active_senders: Vec<String> = self.sender_sessions.keys().cloned().collect();
        let member_ids: Vec<String> = self.members.keys().cloned().collect();
        
        vlog!(VerbosityLevel::Debug, "   - [MULTI-SENDER] Redistribuindo chaves de {} senders", active_senders.len());
        
        for sender_id in &active_senders {
            // Criar nova sessão Megolm outbound para este sender
            let sender = self.members.get_mut(sender_id).unwrap();
            let new_megolm_outbound = sender.crypto.megolm_create_outbound();
            let session_key = sender.crypto.megolm_export_inbound(&new_megolm_outbound);
            
            // BATCH: Coletar todas as chaves cifradas para este sender
            let mut batch_encrypted_keys: Vec<(String, Vec<u8>)> = Vec::new();
            
            for receiver_id in &member_ids {
                if sender_id != receiver_id {
                    // Garantir sessão Olm existe (já deveria existir do setup)
                    self.ensure_olm_session(sender_id, receiver_id)?;
                    
                    // Criptografar chave Megolm via Olm
                    match self.encrypt_megolm_key_via_olm_multi_sender(sender_id, &session_key, receiver_id) {
                        Ok(encrypted_key) => {
                            batch_encrypted_keys.push((receiver_id.clone(), encrypted_key));
                        }
                        Err(e) => {
                            vlog!(VerbosityLevel::Debug, "       - Erro ao criptografar chave de {} para {}: {}", sender_id, receiver_id, e);
                        }
                    }
                }
            }
            
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
                        vlog!(VerbosityLevel::Debug, "       - Erro ao descriptografar chave de {} para {}: {}", sender_id, receiver_id, e);
                    }
                }
            }
            
            // Armazenar nova sessão outbound
            self.sender_sessions.insert(sender_id.clone(), new_megolm_outbound);
            self.message_count_per_sender.insert(sender_id.clone(), 0);
        }

        // ============================================================================
        // FORÇAR AVANÇO ASSIMÉTRICO PQC APENAS DURANTE ROTAÇÕES REAIS
        // ============================================================================
        // COMPORTAMENTO CORRETO:
        // - Durante SETUP inicial: NÃO executar forced ratchet (sessões lazy)
        // - Durante ROTAÇÕES: SIM executar forced ratchet (após warm-up bidirecional)
        //   para garantir forward secrecy PQC a cada redistribuição de chaves Megolm
        // 
        // PRÉ-REQUISITO: warmup_olm_sessions_bidirectional() deve ter sido executado
        // - Warm-up estabelece peer_key em TODAS as sessões outbound
        // - Após warm-up, forced_ratchet pode executar KEM em TODAS as rotações
        //
        // JUSTIFICATIVA:
        // - Sessões outbound recém-criadas (nunca usadas) NÃO têm peer_key ainda
        // - peer_key só é obtido quando:
        //   a) Enviamos primeira mensagem (PreKeyMessage) E
        //   b) Recebemos resposta do peer (com their_ratchet_key)
        // - No setup inicial, TODAS as sessões são lazy (sem peer_key)
        // - Nas rotações, sessões já foram usadas e têm peer_key estabelecido
        // 
        // CONTADORES (apenas durante rotações):
        // - sessions_forced: Sessões PQC que JÁ tinham peer_key e executaram KEM
        // - sessions_lazy: Sessões PQC sem peer_key ainda (KEM na primeira mensagem)
        // - sessions_classical: Sessões sem PQC habilitado
        
        if is_rotation {
            vlog!(VerbosityLevel::Debug, "   - Forçando avanço assimétrico PQC em sessões Olm antes da rotação");
            
            let mut sessions_forced = 0;      // PQC com peer_key: KEM executado
            let mut sessions_lazy = 0;        // PQC sem peer_key: KEM aguarda primeiro uso
            let mut sessions_classical = 0;   // Sem PQC
            
            // Coletar todos os pares (sender_id, receiver_id, outbound_session)
            let mut session_list: Vec<(String, String)> = Vec::new();
            for (sender_id, member) in self.members.iter() {
                for receiver_id in member.olm_sessions.keys() {
                    session_list.push((sender_id.clone(), receiver_id.clone()));
                }
            }
            
            // Processar cada sessão
            for (sender_id, receiver_id) in session_list {
                // SOLUÇÃO CORRETA: Executar forced_ratchet na sessão INBOUND do RECEIVER
                // Motivo: INBOUND tem peer_key estabelecido após receber mensagem do sender
                //         OUTBOUND não tem peer_key até receber resposta
                // 
                // COMPARTILHAMENTO: pending_kem_ciphertext gerado no INBOUND é armazenado
                //                   no OlmSessionPair para ser usado pelo OUTBOUND ao enviar
                if let Some(receiver) = self.members.get_mut(&receiver_id) {
                    if let Some(olm_pair) = receiver.olm_sessions.get_mut(&sender_id) {
                        if let Some(ref mut inbound_session) = olm_pair.inbound {
                            let has_peer_key = inbound_session.has_peer_key();
                            
                            match inbound_session.force_asymmetric_ratchet_advance() {
                                Ok(()) => {
                                    if inbound_session.is_pqc_enabled() {
                                        if has_peer_key {
                                            // Transferir pending_kem_ciphertext do INBOUND para o pair compartilhado
                                            if let Some(pending_kem) = inbound_session.hybrid_session.take_pending_kem_ciphertext() {
                                                olm_pair.pending_kem_for_outbound = Some(pending_kem.clone());
                                                vlog!(VerbosityLevel::Debug, "      └─  Forced ratchet INBOUND {} <- {}: KEM executado ({} bytes) → armazenado no pair", 
                                                     receiver_id, sender_id, pending_kem.len());
                                            }
                                            sessions_forced += 1;
                                        } else {
                                            sessions_lazy += 1;
                                            vlog!(VerbosityLevel::Debug, "      └─  Forced ratchet INBOUND {} <- {}: sem peer_key", 
                                                 receiver_id, sender_id);
                                        }
                                    } else {
                                        sessions_classical += 1;
                                    }
                                }
                                Err(e) => {
                                    vlog!(VerbosityLevel::Debug, "      └─ Erro ao forçar ratchet INBOUND {} <- {}: {:?}", 
                                         receiver_id, sender_id, e);
                                }
                            }
                        }
                    }
                }
            }
            
            vlog!(VerbosityLevel::Debug, "   -  Avanço assimétrico concluído:");
            vlog!(VerbosityLevel::Debug, "      └─ Sessões PQC forçadas: {} (KEM executado - peer_key estabelecido)", sessions_forced);
            vlog!(VerbosityLevel::Debug, "      └─ Sessões PQC lazy: {} (aguardando primeiro uso para KEM)", sessions_lazy);
            vlog!(VerbosityLevel::Debug, "      └─ Sessões clássicas: {} (sem PQC)", sessions_classical);
            
            // Incrementar contador de avanços assimétricos da sala
            self.num_asymmetric_advances += sessions_forced;
            
            // Análise: Esperamos sessions_forced = total após warm-up bidirecional
            if sessions_forced > 0 {
                vlog!(VerbosityLevel::Normal, "   - FORCED RATCHET ATIVO: {} sessões executaram KEM", sessions_forced);
            } else if sessions_lazy > 0 {
                vlog!(VerbosityLevel::Normal, "   -  FORCED RATCHET INATIVO: {} sessões lazy (peer_key não estabelecido)", sessions_lazy);
                vlog!(VerbosityLevel::Normal, "      └─ Warm-up bidirecional deve resolver isso");
            }
        } else {
            vlog!(VerbosityLevel::Debug, "   - Setup inicial: Pulando forced ratchet (sessões Olm ainda não estabelecidas)");
        }

        // Atualizar métricas - TEMPO TOTAL DA ROTAÇÃO (encrypt + decrypt para todos)
        let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
        self.time_rotation_ms += elapsed;
        
        self.current_session_stats.creation_time_ms = 0.0; // Não recria sessões base
        self.current_session_stats.distribution_time_ms = elapsed;

        // MARCAR FIM DA FASE DE ROTAÇÃO
        self.in_rotation_phase = false;
        vlog!(VerbosityLevel::Normal, "   [ROTATION_PHASE] FINALIZADA");

        Ok(())
    }

    /// Rotaciona todas as sessões Megolm (usado após mudanças de membros)
    /// NOTA: Para rotações periódicas (tempo/mensagens), use rotate_megolm_only()
    pub(crate) fn rotate_all_sessions(&mut self, reason: String) -> Result<()> {
        vlog!(VerbosityLevel::Verbose, "   - Rotacionando todas as sessões Megolm (razão: {})", reason);
        
        // Arquivar estatísticas da sessão atual
        if !self.sender_sessions.is_empty() {
            self.session_history.push(std::mem::take(&mut self.current_session_stats));
            self.rotation_count += 1; // Incrementar contador de rotações
        }

        // Resetar contadores para nova sessão (CRÍTICO!)
        self.message_count = 0;
        self.message_count_per_sender.clear();
        self.session_start_time = std::time::Instant::now();

        // Recriar todas as sessões (Olm + Megolm) - apenas quando necessário
        self.sender_sessions.clear();
        self.create_sessions()
    }

    /// Garante que existe sessão Olm OUTBOUND entre sender e receiver
    /// Inbound session será criada lazy durante primeira descriptografia
    pub(crate) fn ensure_olm_session(&mut self, sender_id: &str, receiver_id: &str) -> Result<()> {
        // Verificar se já existe sessão outbound
        let needs_creation = if let Some(sender) = self.members.get(sender_id) {
            if let Some(pair) = sender.olm_sessions.get(receiver_id) {
                let has_outbound = pair.has_outbound();
                if !has_outbound {
                    vlog!(VerbosityLevel::Debug, "     - [ENSURE_OLM] Sessão {} -> {} NÃO existe, criando NOVA", 
                         sender_id, receiver_id);
                } else {
                    // Verificar status de peer_key na sessão INBOUND do RECEIVER
                    // (pois é lá que has_received_message() fica true)
                    let peer_key_status = if let Some(receiver) = self.members.get(receiver_id) {
                        if let Some(receiver_pair) = receiver.olm_sessions.get(sender_id) {
                            if let Some(ref inbound) = receiver_pair.inbound {
                                if inbound.has_peer_key() {
                                    " COM peer_key PQC no inbound"
                                } else if inbound.has_received_message_classic() {
                                    " Inbound recebeu mensagem (pronto)"
                                } else {
                                    " SEM peer_key no inbound (lazy)"
                                }
                            } else {
                                " Receiver não tem inbound"
                            }
                        } else {
                            " Receiver não tem par Olm"
                        }
                    } else {
                        " Receiver não encontrado"
                    };
                    vlog!(VerbosityLevel::Debug, "     - [ENSURE_OLM] Sessão {} -> {} JÁ existe, reutilizando [{}]", 
                         sender_id, receiver_id, peer_key_status);
                }
                !has_outbound
            } else {
                vlog!(VerbosityLevel::Debug, "     - [ENSURE_OLM] Par Olm {} -> {} não encontrado, criando NOVO", 
                     sender_id, receiver_id);
                true
            }
        } else {
            return Err(anyhow::anyhow!("Sender {} não encontrado", sender_id));
        };

        if needs_creation {
            // LAZY: Criar APENAS sessão outbound (inbound será criada em decrypt)
            let (outbound_session, init_message_opt) = self.create_outbound_olm_session_only(sender_id, receiver_id)?;
            
            vlog!(VerbosityLevel::Debug, "     - [ENSURE_OLM]  NOVA sessão Olm criada: {} -> {} (peer_key será perdido!)", 
                 sender_id, receiver_id);
            
            // TRANSMITIR init_message para o receiver (se híbrido)
            if let Some(init_msg) = init_message_opt {
                if let Some(receiver) = self.members.get_mut(receiver_id) {
                    receiver.crypto.set_pqxdh_init_message(init_msg);
                    vlog!(VerbosityLevel::Debug, "     - [LAZY] Init message transmitida: {} -> {}", 
                         sender_id, receiver_id);
                }
            }
            
            // Armazenar outbound no sender
            if let Some(sender) = self.members.get_mut(sender_id) {
                let pair = sender.olm_sessions.entry(receiver_id.to_string())
                    .or_insert_with(OlmSessionPair::new);
                pair.outbound = Some(outbound_session);
            }
            
            // NOTA: Inbound session será criada lazy em decrypt_megolm_key_via_olm_multi_sender
            // via create_inbound_session() quando a primeira PreKeyMessage chegar
        }

        Ok(())
    }
    /// Verifica se rotação é necessária
    pub(crate) fn should_rotate(&self) -> Option<String> {
        if self.sender_sessions.is_empty() {
            return None;
        }

        // Verificar limite de mensagens
        if self.message_count >= self.rotation_config.max_messages {
            return Some(format!("message_limit:{}", self.message_count));
        }

        // Verificar limite de tempo
        let session_age_ms = self.session_start_time.elapsed().as_millis() as u64;
        if session_age_ms >= self.rotation_config.max_age_ms {
            return Some(format!("time_limit:{}ms", session_age_ms));
        }

        None
    }
}
