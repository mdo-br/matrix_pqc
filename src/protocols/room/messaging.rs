#![allow(unused_imports, dead_code)]

use anyhow::{Result, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::crypto::{CryptoProvider, OlmSessionHandle, MegolmOutbound};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::*;

#[allow(dead_code)]
impl MatrixRoom {
    /// Send a message from `sender_id` with plaintext `content`. Returns the encrypted message bytes.
    pub fn send_message(&mut self, sender_id: &str, content: &[u8]) -> Result<Vec<u8>> {
        let start_time = std::time::Instant::now();
        
        if let Some(reason) = self.should_rotate() {
            self.rotate_megolm_only(reason)?;
        }

        let sender = self.members.get_mut(sender_id)
            .context(format!("Sender {} not found", sender_id))?;

        let sender_session = self.sender_sessions.get_mut(sender_id)
            .context(format!("Outbound session not found for {}", sender_id))?;

        // Encrypt and account for Megolm message bandwidth.
        let encrypted = sender.crypto.megolm_encrypt(sender_session, content);
        
        let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
        self.time_messages_ms += elapsed;
        
        self.bandwidth_messages += encrypted.len();
        self.bandwidth_megolm_messages += encrypted.len();
        self.bandwidth_data_plane += encrypted.len();
        
        // Refresh Megolm session stats
        self.current_session_stats.messages_encrypted += 1;
        self.current_session_stats.total_bytes_encrypted += encrypted.len();
        self.message_count += 1;
        *self.message_count_per_sender.entry(sender_id.to_string()).or_insert(0) += 1;

        Ok(encrypted)
    }

    pub fn decrypt_message(&mut self, receiver_id: &str, encrypted_message: &[u8]) -> Result<Vec<u8>> {
        let member = self.members.get_mut(receiver_id)
            .context("Member not found")?;

        let megolm_inbound = member.megolm_inbound.as_mut()
            .context("Megolm inbound session not initialised")?;

        member.crypto.megolm_decrypt(megolm_inbound, encrypted_message)
            .map_err(|e| anyhow::anyhow!("Decryption error: {:?}", e))
    }

    /// Returns bandwidth metrics (bytes transmitted)
    pub fn get_bandwidth_metrics(&self) -> (usize, usize, usize, usize) {
        // (key_exchange_bytes, session_distribution_bytes, rekeying_bytes, message_bytes)
        (self.bandwidth_key_exchange, self.bandwidth_session_distribution, self.bandwidth_rekeying, self.bandwidth_messages)
    }

    /// Returns time metrics (ms) - ALIGNED WITH BANDWIDTH
    pub fn get_time_metrics(&self) -> (f64, f64, f64, f64) {
        // (agreement_ms, initial_distribution_ms, rotation_ms, messages_ms)
        (self.time_agreement_ms, self.time_initial_distribution_ms, self.time_rotation_ms, self.time_messages_ms)
    }
}
