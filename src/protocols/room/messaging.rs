#![allow(unused_imports, dead_code)]

use anyhow::{Result, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::crypto::{CryptoProvider, OlmSessionHandle, MegolmOutbound};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::*;

#[allow(dead_code)]
impl MatrixRoom {
    /// Envia mensagem na sala (com rotação automática)
    pub fn send_message(&mut self, sender_id: &str, content: &[u8]) -> Result<Vec<u8>> {
        let start_time = std::time::Instant::now();
        
        // Verificar se rotação é necessária (usa rotate_megolm_only para preservar Olm)
        if let Some(reason) = self.should_rotate() {
            self.rotate_megolm_only(reason)?;
        }

        // Obter sessão Megolm do sender
        let sender = self.members.get_mut(sender_id)
            .context(format!("Sender {} não encontrado", sender_id))?;

        let sender_session = self.sender_sessions.get_mut(sender_id)
            .context(format!("Sessão outbound não encontrada para {}", sender_id))?;

        // Criptografar mensagem
        let encrypted = sender.crypto.megolm_encrypt(sender_session, content);
        
        // Medir tempo
        let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
        self.time_messages_ms += elapsed;
        
        // Rastrear largura de banda: mensagem Megolm criptografada (LEGACY)
        self.bandwidth_messages += encrypted.len();
        
        // ============= NOVAS MÉTRICAS =============
        // COMPARAÇÃO 1.4: Mensagens Megolm (AES-256 + HMAC-SHA-256)
        // NÃO HÁ OVERHEAD PQC - Megolm usa criptografia simétrica em AMBOS os modos!
        self.bandwidth_megolm_messages += encrypted.len();
        
        // COMPARAÇÃO 2: DADOS (plano de dados - mensagens da sala)
        self.bandwidth_data_plane += encrypted.len();
        
        // Atualizar estatísticas
        self.current_session_stats.messages_encrypted += 1;
        self.current_session_stats.total_bytes_encrypted += encrypted.len();
        self.message_count += 1;
        *self.message_count_per_sender.entry(sender_id.to_string()).or_insert(0) += 1;

        Ok(encrypted)
    }

    /// Descriptografa mensagem recebida
    pub fn decrypt_message(&mut self, receiver_id: &str, encrypted_message: &[u8]) -> Result<Vec<u8>> {
        let member = self.members.get_mut(receiver_id)
            .context("Membro não encontrado")?;

        let megolm_inbound = member.megolm_inbound.as_mut()
            .context("Sessão Megolm inbound não inicializada")?;

        member.crypto.megolm_decrypt(megolm_inbound, encrypted_message)
            .map_err(|e| anyhow::anyhow!("Erro na descriptografia: {:?}", e))
    }

    /// Retorna métricas de largura de banda (bytes transmitidos)
    pub fn get_bandwidth_metrics(&self) -> (usize, usize, usize, usize) {
        // (key_exchange_bytes, session_distribution_bytes, rekeying_bytes, message_bytes)
        (self.bandwidth_key_exchange, self.bandwidth_session_distribution, self.bandwidth_rekeying, self.bandwidth_messages)
    }

    /// Retorna métricas de tempo acumuladas (ms) - ALINHADO COM LARGURA DE BANDA
    pub fn get_time_metrics(&self) -> (f64, f64, f64, f64) {
        // (agreement_ms, initial_distribution_ms, rotation_ms, messages_ms)
        (self.time_agreement_ms, self.time_initial_distribution_ms, self.time_rotation_ms, self.time_messages_ms)
    }
}
