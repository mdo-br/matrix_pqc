#![allow(unused_imports, dead_code)]

use anyhow::{Result, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::crypto::{CryptoProvider, OlmSessionHandle, MegolmOutbound};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::*;

#[allow(dead_code)]
impl MatrixRoom {
    /// Criptografa chave Megolm via canal Olm no modo multi-sender
    pub(crate) fn encrypt_megolm_key_via_olm_multi_sender(&mut self, sender_id: &str, session_key: &[u8], receiver_id: &str) -> Result<Vec<u8>> {
        let start_time = std::time::Instant::now();
        
        vlog!(VerbosityLevel::Verbose, "      [ENCRYPT_CALL] {} -> {}", sender_id, receiver_id);
        
        let sender = self.members.get_mut(sender_id)
            .context("Sender não encontrado")?;
        
        let olm_session_pair = sender.olm_sessions.get_mut(receiver_id)
            .context("Sessão Olm não encontrada")?;
        
        // SOLUÇÃO: Aplicar pending_kem_for_outbound antes de criptografar
        // O INBOUND gerou o KEM durante forced_ratchet e armazenou no pair
        // O OUTBOUND vai usar esse KEM ao enviar a mensagem
        if let Some(pending_kem) = olm_session_pair.pending_kem_for_outbound.take() {
            if let Some(ref mut olm_session) = olm_session_pair.outbound {
                olm_session.hybrid_session.set_pending_kem_ciphertext(pending_kem.clone());
                vlog!(VerbosityLevel::Debug, "       [ENCRYPT] {} -> {}: Usando KEM compartilhado do INBOUND ({} bytes)", 
                     sender_id, receiver_id, pending_kem.len());
            }
        }
        
        let olm_session = olm_session_pair.get_outbound_mut()
            .context("Sessão Olm outbound não encontrada")?;

        //Medir avanços do Double Ratchet ANTES
        let ratchet_before = olm_session.get_ratchet_advances();
        let asymmetric_before = olm_session.get_asymmetric_advances();

        let encrypted_key = sender.crypto.olm_encrypt(olm_session, session_key);

        // LOG DETALHADO: Breakdown da mensagem
        vlog!(VerbosityLevel::Debug, "       [ENCRYPT_BREAKDOWN] {} -> {}:", sender_id, receiver_id);
        vlog!(VerbosityLevel::Debug, "         └─ Total message size: {} bytes", encrypted_key.len());
        vlog!(VerbosityLevel::Debug, "         └─ Session key payload: {} bytes", session_key.len());
        vlog!(VerbosityLevel::Debug, "         └─ Is PQC enabled: {}", olm_session.is_pqc_enabled());
        vlog!(VerbosityLevel::Debug, "         └─ Has peer key: {}", olm_session.has_peer_key());
        
        // Tentar decodificar JSON para ver tipo de mensagem e breakdown detalhado
        if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&encrypted_key) {
            if let Some(msg_type) = json_val.get("type").and_then(|t| t.as_u64()) {
                vlog!(VerbosityLevel::Debug, "         └─ Message type: {}", msg_type);
                if let Some(body) = json_val.get("body").and_then(|b| b.as_str()) {
                    vlog!(VerbosityLevel::Debug, "         └─ Body (base64) length: {} chars", body.len());
                    if let Ok(decoded) = B64.decode(body) {
                        vlog!(VerbosityLevel::Debug, "         └─ Body (decoded) length: {} bytes", decoded.len());
                        
                        // Se tipo 2 (PQC), parsear estrutura interna
                        if msg_type == 2 && decoded.len() >= 19 {
                            let mut offset = 0;
                            
                            // Version (1B)
                            let version = decoded[offset];
                            offset += 1;
                            vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] Version: {}", version);
                            
                            // Classic type (1B)
                            let classic_type = decoded[offset];
                            offset += 1;
                            vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] Classic msg type: {}", classic_type);
                            
                            // Classic length (4B)
                            if decoded.len() >= offset + 4 {
                                let classic_len = u32::from_le_bytes([
                                    decoded[offset], decoded[offset + 1], 
                                    decoded[offset + 2], decoded[offset + 3]
                                ]) as usize;
                                offset += 4;
                                vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] Classic payload: {} bytes", classic_len);
                                
                                if decoded.len() >= offset + classic_len + 5 {  // +4 for msg_index (u32) +1 for pqc_enabled
                                    offset += classic_len; // Skip classic payload
                                    vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] After classic: offset={}", offset);
                                    offset += 4; // Skip msg_index (u32, not u64!)
                                    vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] After msg_index: offset={}", offset);
                                    
                                    let pqc_enabled = decoded[offset];
                                    offset += 1;
                                    vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] PQC enabled byte at {}: {}", offset-1, pqc_enabled);
                                    vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] Remaining bytes: {}", decoded.len() - offset);
                                    
                                    if pqc_enabled == 1 && decoded.len() >= offset + 4 {
                                        // Ratchet key length (4B)
                                        let ratchet_key_len = u32::from_le_bytes([
                                            decoded[offset], decoded[offset + 1], 
                                            decoded[offset + 2], decoded[offset + 3]
                                        ]) as usize;
                                        offset += 4;
                                        vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] Ratchet key: {} bytes", ratchet_key_len);
                                        
                                        if decoded.len() >= offset + ratchet_key_len + 4 {
                                            offset += ratchet_key_len; // Skip ratchet key
                                            
                                            // KEM ciphertext length (4B)
                                            let kem_ct_len = u32::from_le_bytes([
                                                decoded[offset], decoded[offset + 1], 
                                                decoded[offset + 2], decoded[offset + 3]
                                            ]) as usize;
                                            vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] KEM ciphertext: {} bytes ", kem_ct_len);
                                            
                                            vlog!(VerbosityLevel::Debug, "         └─ [SUMMARY]:");
                                            vlog!(VerbosityLevel::Debug, "            ├─ Payload (Megolm key): {} bytes", classic_len);
                                            vlog!(VerbosityLevel::Debug, "            ├─ Ratchet key (classic): {} bytes", ratchet_key_len);
                                            vlog!(VerbosityLevel::Debug, "            ├─ KEM ciphertext (PQC): {} bytes", kem_ct_len);
                                            vlog!(VerbosityLevel::Debug, "            └─ Overhead (headers/MAC): {} bytes", 
                                                 decoded.len() - classic_len - ratchet_key_len - kem_ct_len - 19);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        
        //  Medir avanços do Double Ratchet DEPOIS
        let ratchet_after = olm_session.get_ratchet_advances();
        let asymmetric_after = olm_session.get_asymmetric_advances();
        
        //  Atualizar contadores globais da sala
        if ratchet_after > ratchet_before {
            self.num_ratchet_advances += (ratchet_after - ratchet_before) as usize;
        }
        if asymmetric_after > asymmetric_before {
            self.num_asymmetric_advances += (asymmetric_after - asymmetric_before) as usize;
        }
        
        // Log detalhado para análise de acordos
        vlog!(VerbosityLevel::Debug, "       [ENCRYPT] Room: {}, Sender: {} -> {}, Size: {} bytes, in_setup: {}, Mode: {:?}", 
                 self.room_id, sender_id, receiver_id, encrypted_key.len(), self.in_setup_phase, self.crypto_mode);
        
        // Debug: classificação da mensagem
        if encrypted_key.len() > 1500 {
            vlog!(VerbosityLevel::Debug, "         └─Mensagem PQC detectada (>1500B): {} bytes", encrypted_key.len());
        } else {
            vlog!(VerbosityLevel::Debug, "         └─Mensagem clássica (<1500B): {} bytes", encrypted_key.len());
        }
        
        // Rastrear largura de banda: diferenciar PreKey (setup) e Message (pode ter rekeying)
        // As mensagens Olm vêm em formato base64. Precisamos decodificar para verificar o tipo JSON interno
        // Formato das mensagens Olm:
        // - Clássico PreKeyMessage (tipo 0): {"type":0,"body":"..."} - 3DH, ~300-500 bytes
        // - Clássico Message (tipo 1): {"type":1,"body":"..."} - ratchet clássico, ~200-400 bytes
        // - Híbrido Message PQC (tipo 2): {"type":2,"body":"..."} - pode ter rekeying Kyber-768
        
        // Extrair breakdown REAL dos componentes da mensagem PQC
        let (classical_bytes, pqc_bytes) = Self::extract_message_breakdown(&encrypted_key, &self.crypto_mode);
        
        let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;

        if self.in_setup_phase {
            // Durante setup inicial: conta como parte da distribuição de sessão Megolm
            self.bandwidth_session_distribution += encrypted_key.len();
            self.time_initial_distribution_ms += elapsed;
            
            // NOVAS MÉTRICAS: COMPARAÇÃO 1.2 - DISTRIBUIÇÃO INICIAL (Protocolo Completo)
            self.bandwidth_initial_distribution += encrypted_key.len();
            self.bandwidth_initial_distribution_classical += classical_bytes;
            self.bandwidth_initial_distribution_pqc += pqc_bytes;
            self.bandwidth_control_plane += encrypted_key.len();
            
            // ============================================================================
            // PRIMITIVAS ISOLADAS: Extrair componentes da distribuição inicial
            // ============================================================================
            // Similar à rotação, mas é a primeira distribuição da session key
            
            let megolm_key_size = 308;
            self.bandwidth_initial_distribution_primitives_megolm_key += megolm_key_size;
            
            // Extrair ratchet key e KEM CT de acordo com tipo da mensagem
            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&encrypted_key) {
                let msg_type_val = json_val.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
                if msg_type_val == 2 {
                    // PQC (type 2): parsear estrutura interna PqcOlmMessage
                    if let Some(body) = json_val.get("body").and_then(|b| b.as_str()) {
                        if let Ok(decoded) = B64.decode(body) {
                            if decoded.len() >= 19 {
                                let mut offset = 0;
                                offset += 1; // version
                                offset += 1; // type

                                if decoded.len() >= offset + 4 {
                                    let classic_len = u32::from_le_bytes([
                                        decoded[offset], decoded[offset+1],
                                        decoded[offset+2], decoded[offset+3]
                                    ]) as usize;
                                    offset += 4;

                                    if decoded.len() >= offset + classic_len + 5 {
                                        offset += classic_len;
                                        offset += 4; // msg_index

                                        let pqc_enabled = decoded[offset];
                                        offset += 1;

                                        if pqc_enabled == 1 && decoded.len() >= offset + 4 {
                                            let ratchet_key_len = u32::from_le_bytes([
                                                decoded[offset], decoded[offset+1],
                                                decoded[offset+2], decoded[offset+3]
                                            ]) as usize;
                                            offset += 4;

                                            self.bandwidth_initial_distribution_primitives_ratchet_key += ratchet_key_len;

                                            if decoded.len() >= offset + ratchet_key_len + 4 {
                                                offset += ratchet_key_len;

                                                let kem_ct_len = u32::from_le_bytes([
                                                    decoded[offset], decoded[offset+1],
                                                    decoded[offset+2], decoded[offset+3]
                                                ]) as usize;

                                                self.bandwidth_initial_distribution_primitives_kem_ct += kem_ct_len;

                                                let primitives_sum = megolm_key_size + ratchet_key_len + kem_ct_len;
                                                if encrypted_key.len() > primitives_sum {
                                                    self.bandwidth_initial_distribution_primitives_olm_overhead +=
                                                        encrypted_key.len() - primitives_sum;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Classical (type 0 ou 1): ratchet key 32B, sem KEM CT
                    let classical_ratchet_size = 32;
                    self.bandwidth_initial_distribution_primitives_ratchet_key += classical_ratchet_size;
                    let primitives_sum = megolm_key_size + classical_ratchet_size;
                    if encrypted_key.len() > primitives_sum {
                        self.bandwidth_initial_distribution_primitives_olm_overhead +=
                            encrypted_key.len() - primitives_sum;
                    }
                }
            }
        } else if self.in_rotation_phase {
            // Durante rotação: apenas mensagens DENTRO de rotate_megolm_only()
            // CORREÇÃO: Ambos (Classical e Hybrid) devem contar APENAS mensagens de rotação
            self.bandwidth_rekeying += encrypted_key.len();
            self.time_rotation_ms += elapsed;
            
            // NOVAS MÉTRICAS: COMPARAÇÃO 1.3 - ROTAÇÃO (Protocolo Completo)
            self.bandwidth_rotation += encrypted_key.len();
            self.bandwidth_rotation_classical += classical_bytes;
            self.bandwidth_rotation_pqc += pqc_bytes;
            self.bandwidth_control_plane += encrypted_key.len();
            
            // ============================================================================
            // PRIMITIVAS ISOLADAS: Extrair componentes da mensagem de rotação
            // ============================================================================
            // A mensagem contém: Megolm key (308B) + Ratchet key + KEM ciphertext
            // Vamos parsear para extrair cada componente
            
            // Megolm session key é sempre 308B (idêntico em Classical e Hybrid)
            let megolm_key_size = 308;
            self.bandwidth_rotation_primitives_megolm_key += megolm_key_size;
            
            // Extrair ratchet key e KEM CT de acordo com tipo da mensagem
            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&encrypted_key) {
                let msg_type_val = json_val.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
                if msg_type_val == 2 {
                    // PQC (type 2): parsear estrutura interna PqcOlmMessage
                    if let Some(body) = json_val.get("body").and_then(|b| b.as_str()) {
                        if let Ok(decoded) = B64.decode(body) {
                            if decoded.len() >= 19 {
                                let mut offset = 0;
                                offset += 1; // version
                                offset += 1; // type

                                if decoded.len() >= offset + 4 {
                                    let classic_len = u32::from_le_bytes([
                                        decoded[offset], decoded[offset+1],
                                        decoded[offset+2], decoded[offset+3]
                                    ]) as usize;
                                    offset += 4;

                                    if decoded.len() >= offset + classic_len + 5 {
                                        offset += classic_len;
                                        offset += 4; // msg_index

                                        let pqc_enabled = decoded[offset];
                                        offset += 1;

                                        if pqc_enabled == 1 && decoded.len() >= offset + 4 {
                                            let ratchet_key_len = u32::from_le_bytes([
                                                decoded[offset], decoded[offset+1],
                                                decoded[offset+2], decoded[offset+3]
                                            ]) as usize;
                                            offset += 4;

                                            self.bandwidth_rotation_primitives_ratchet_key += ratchet_key_len;

                                            if decoded.len() >= offset + ratchet_key_len + 4 {
                                                offset += ratchet_key_len;

                                                let kem_ct_len = u32::from_le_bytes([
                                                    decoded[offset], decoded[offset+1],
                                                    decoded[offset+2], decoded[offset+3]
                                                ]) as usize;

                                                self.bandwidth_rotation_primitives_kem_ct += kem_ct_len;

                                                let primitives_sum = megolm_key_size + ratchet_key_len + kem_ct_len;
                                                if encrypted_key.len() > primitives_sum {
                                                    self.bandwidth_rotation_primitives_olm_overhead +=
                                                        encrypted_key.len() - primitives_sum;
                                                }

                                                vlog!(VerbosityLevel::Debug,
                                                      "         └─[PRIMITIVES] Megolm={}B, Ratchet={}B, KEM={}B, Overhead={}B",
                                                      megolm_key_size, ratchet_key_len, kem_ct_len,
                                                      encrypted_key.len() - primitives_sum);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Classical (type 0 ou 1): ratchet key 32B, sem KEM CT
                    let classical_ratchet_size = 32;
                    self.bandwidth_rotation_primitives_ratchet_key += classical_ratchet_size;
                    let primitives_sum = megolm_key_size + classical_ratchet_size;
                    if encrypted_key.len() > primitives_sum {
                        self.bandwidth_rotation_primitives_olm_overhead +=
                            encrypted_key.len() - primitives_sum;
                    }
                    vlog!(VerbosityLevel::Debug,
                          "         └─[PRIMITIVES CLASSICAL] Megolm={}B, Ratchet={}B, Overhead={}B",
                          megolm_key_size, classical_ratchet_size,
                          encrypted_key.len().saturating_sub(primitives_sum));
                }
            }
            
            // CONTADOR REAL de mensagens de rotação
            self.num_rotation_messages += 1;
            
            vlog!(VerbosityLevel::Normal, 
                  "      [ROTATION_MSG] {} -> {}: {} bytes (classical={}, pqc={}) [msg #{}]", 
                  sender_id, receiver_id, encrypted_key.len(), classical_bytes, pqc_bytes, 
                  self.num_rotation_messages);
        } else {
            // Fora de setup e rotação: mensagens normais (warm-up, re-sends, etc.)
            // Não conta como overhead de rotação
            self.bandwidth_messages += encrypted_key.len();
            self.time_messages_ms += elapsed;
            self.bandwidth_control_plane += encrypted_key.len();
        }
        
        Ok(encrypted_key)
    }

    /// Descriptografa chave Megolm via canal Olm no modo multi-sender
    pub(crate) fn decrypt_megolm_key_via_olm_multi_sender(&mut self, encrypted_key: &[u8], receiver_id: &str, sender_id: &str) -> Result<Vec<u8>> {
        // Obter identidades do sender ANTES do borrow mutable
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
                //  Medir avanços ANTES
                let ratchet_before = inbound_session.get_ratchet_advances();
                let asymmetric_before = inbound_session.get_asymmetric_advances();
                
                // Tentar usar sessão inbound existente
                match receiver.crypto.olm_decrypt(inbound_session, encrypted_key) {
                    Ok(decrypted_bytes) => {
                        //  Medir avanços DEPOIS
                        let ratchet_after = inbound_session.get_ratchet_advances();
                        let asymmetric_after = inbound_session.get_asymmetric_advances();
                        
                        //  Atualizar contadores globais
                        if ratchet_after > ratchet_before {
                            self.num_ratchet_advances += (ratchet_after - ratchet_before) as usize;
                        }
                        if asymmetric_after > asymmetric_before {
                            self.num_asymmetric_advances += (asymmetric_after - asymmetric_before) as usize;
                        }
                        
                        return Ok(decrypted_bytes);
                    }
                    Err(_) => {
                        // Falha na sessão existente - pode ser PreKeyMessage
                        // Continuar para criar nova sessão
                    }
                }
            }
        }

        // Criar nova sessão Olm inbound (primeira mensagem ou sessão expirada)
        match receiver.crypto.create_inbound_session(&sender_identity_keys.curve25519, encrypted_key) {
            Ok((inbound_session, decrypted_bytes)) => {
                //  Medir avanços na sessão recém-criada (marca setup assimétrico)
                let ratchet_count = inbound_session.get_ratchet_advances();
                let asymmetric_count = inbound_session.get_asymmetric_advances();
                
                //  Atualizar contadores globais (setup conta como assimétrico)
                self.num_ratchet_advances += ratchet_count as usize;
                self.num_asymmetric_advances += asymmetric_count as usize;
                
                // Armazenar a nova sessão inbound para reutilização futura
                let pair = receiver.olm_sessions.entry(sender_id.to_string())
                    .or_insert_with(OlmSessionPair::new);
                pair.inbound = Some(inbound_session);
                
                Ok(decrypted_bytes)
            }
            Err(e) => {
                Err(anyhow::anyhow!("Falha na descriptografia de {} para {}: {}", sender_id, receiver_id, e))
            }
        }
    }
    /// Extrai breakdown REAL de uma mensagem Olm criptografada
    /// Retorna: (classical_bytes, pqc_bytes)
    fn extract_message_breakdown(encrypted_message: &[u8], crypto_mode: &CryptoMode) -> (usize, usize) {
        // Para Classical: toda mensagem é clássica
        if *crypto_mode == CryptoMode::Classical {
            return (encrypted_message.len(), 0);
        }
        
        vlog!(VerbosityLevel::Debug, "         └─[EXTRACT] Analisando mensagem de {} bytes", encrypted_message.len());
        
        // Para Hybrid: tentar decodificar o JSON e extrair componentes reais
        if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(encrypted_message) {
            if let Some(msg_type) = json_val.get("type").and_then(|t| t.as_u64()) {
                vlog!(VerbosityLevel::Debug, "            ├─ Tipo JSON: {}", msg_type);
                if let Some(body) = json_val.get("body").and_then(|b| b.as_str()) {
                    // Decodificar base64 do body
                    if let Ok(decoded_bytes) = B64.decode(body) {
                        // Tentar deserializar como PqcOlmMessage para obter breakdown real
                        // O formato interno é: [version][vodozemac_msg][pqc_data]
                        
                        // Se tipo 2 (PQC), parsear estrutura real
                        // Formato: [1B version][1B classic_type][4B classic_len][classic_bytes][8B msg_index][1B pqc_enabled][4B ratchet_key_len][ratchet_key_bytes][4B kem_ct_len][kem_ct_bytes]
                        if msg_type == 2 && decoded_bytes.len() >= 19 {
                            let mut offset = 0;
                            
                            vlog!(VerbosityLevel::Debug, "            ├─ [PARSE] Total decoded: {} bytes", decoded_bytes.len());
                            vlog!(VerbosityLevel::Debug, "            ├─ [PARSE] Primeiros 20 bytes: {:?}", &decoded_bytes[..20.min(decoded_bytes.len())]);
                            
                            // 1. Version (1B)
                            let version = decoded_bytes[offset];
                            offset += 1;
                            vlog!(VerbosityLevel::Debug, "            ├─ [PARSE] Version: {}", version);
                            
                            // 2. Classic type (1B)
                            let classic_type = decoded_bytes[offset];
                            offset += 1;
                            vlog!(VerbosityLevel::Debug, "            ├─ [PARSE] Classic type: {}", classic_type);
                            
                            // 3. Classic length (4B)
                            if decoded_bytes.len() < offset + 4 {
                                return (decoded_bytes.len(), 0);
                            }
                            let classic_len = u32::from_le_bytes([
                                decoded_bytes[offset],
                                decoded_bytes[offset + 1],
                                decoded_bytes[offset + 2],
                                decoded_bytes[offset + 3],
                            ]) as usize;
                            vlog!(VerbosityLevel::Debug, "            ├─ [PARSE] Classic len: {} bytes (offset {})", classic_len, offset);
                            offset += 4;
                            
                            // 4. Classic bytes
                            if decoded_bytes.len() < offset + classic_len {
                                vlog!(VerbosityLevel::Debug, "            └─ [PARSE]  Não há bytes suficientes para classic payload");
                                return (decoded_bytes.len(), 0);
                            }
                            let classical_bytes = classic_len;
                            vlog!(VerbosityLevel::Debug, "            ├─ [PARSE] Pulando {} bytes de classic payload (offset {}->{})", classic_len, offset, offset + classic_len);
                            offset += classic_len;
                            
                            // 5. Message index (4B, not 8B!) + pqc_enabled (1B)
                            if decoded_bytes.len() < offset + 5 {
                                vlog!(VerbosityLevel::Debug, "            └─ [PARSE]  Não há bytes suficientes para msg_index+pqc_enabled");
                                return (classical_bytes, 0);
                            }
                            vlog!(VerbosityLevel::Debug, "            ├─ [PARSE] Pulando msg_index(4B)+pqc_enabled(1B) (offset {}->{})", offset, offset + 5);
                            offset += 5;
                            
                            // 6. Todo o restante é componente PQC (ratchet_key_len + ratchet_key + kem_ct_len + kem_ct)
                            let pqc_bytes = decoded_bytes.len().saturating_sub(offset);
                            
                            vlog!(VerbosityLevel::Debug, "         └─[BREAKDOWN REAL PARSEADO] Total: {} bytes, Classical: {} bytes, PQC: {} bytes (offset {}, restantes: {})",
                                 decoded_bytes.len(), classical_bytes, pqc_bytes, offset, decoded_bytes.len() - offset);
                            
                            return (classical_bytes, pqc_bytes);
                        }
                        
                        // Tipo 0 ou 1: clássico com possível upgrade PQC
                        // Neste caso, usar tamanho decodificado como clássico
                        return (decoded_bytes.len(), 0);
                    }
                }
            }
        }
        
        // Fallback: usar heurística de tamanho
        // Mensagens > 1500 bytes geralmente têm componente PQC
        if encrypted_message.len() > 1500 {
            // Estimativa conservadora: ~500 bytes clássico base + resto PQC
            let estimated_classical = 500;
            let estimated_pqc = encrypted_message.len().saturating_sub(estimated_classical);
            
            vlog!(VerbosityLevel::Debug, "         └─[BREAKDOWN HEURÍSTICA] Classical: ~{} bytes, PQC: ~{} bytes", 
                 estimated_classical, estimated_pqc);
            
            (estimated_classical, estimated_pqc)
        } else {
            // Mensagens pequenas: apenas clássico
            (encrypted_message.len(), 0)
        }
    }
}
