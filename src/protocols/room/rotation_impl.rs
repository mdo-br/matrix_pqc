#![allow(unused_imports, dead_code)]

use anyhow::{Result, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::crypto::{CryptoProvider, OlmSessionHandle, MegolmOutbound};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::*;

#[allow(dead_code)]
impl MatrixRoom {
    /// Rotates only the Megolm sessions of active senders, preserving existing Olm sessions.
    pub(crate) fn rotate_megolm_only(&mut self, reason: String) -> Result<()> {
        let start_time = std::time::Instant::now();
        vlog!(VerbosityLevel::Verbose, "Rotating Megolm sessions (reason: {})", reason);
        
        self.in_rotation_phase = true;
        
        let is_rotation = !self.sender_sessions.is_empty();
        
        if is_rotation {
            self.session_history.push(std::mem::take(&mut self.current_session_stats));
            self.rotation_count += 1;
        }

        self.message_count = 0;
        self.message_count_per_sender.clear();
        self.session_start_time = std::time::Instant::now();

        // Each active sender creates a fresh Megolm outbound session and distributes
        // its key to every other member via their existing Olm channels.
        let active_senders: Vec<String> = self.sender_sessions.keys().cloned().collect();
        let member_ids: Vec<String> = self.members.keys().cloned().collect();
        
        vlog!(VerbosityLevel::Debug, "Multi-sender rotation: {} senders", active_senders.len());
        
        for sender_id in &active_senders {
            // Create a fresh Megolm outbound session for this sender.
            let sender = self.members.get_mut(sender_id).unwrap();
            let new_megolm_outbound = sender.crypto.megolm_create_outbound();
            let session_key = sender.crypto.megolm_export_inbound(&new_megolm_outbound);
            
            // BATCH: Colect cipher keys for all receivers before decrypting any --- more efficient than interleaving encrypt-decrypt per receiver
            let mut batch_encrypted_keys: Vec<(String, Vec<u8>)> = Vec::new();
            
            for receiver_id in &member_ids {
                if sender_id != receiver_id {
                    self.ensure_olm_session(sender_id, receiver_id)?;
                    
                    match self.encrypt_megolm_key_via_olm_multi_sender(sender_id, &session_key, receiver_id) {
                        Ok(encrypted_key) => {
                            batch_encrypted_keys.push((receiver_id.clone(), encrypted_key));
                        }
                        Err(e) => {
                            vlog!(VerbosityLevel::Debug, "Key encrypt error {} -> {}: {}", sender_id, receiver_id, e);
                        }
                    }
                }
            }
            
            // RECEIVE: Each receiver decrypts the new session key via Olm and imports it as a new Megolm inbound session, replacing the old one.
            for (receiver_id, encrypted_key) in batch_encrypted_keys {
                match self.decrypt_megolm_key_via_olm_multi_sender(&encrypted_key, &receiver_id, sender_id) {
                    Ok(decrypted_key) => {
                        if let Some(receiver) = self.members.get_mut(&receiver_id) {
                            let megolm_inbound = receiver.crypto.megolm_import_inbound(&decrypted_key);
                            receiver.megolm_inbound = Some(megolm_inbound);
                        }
                    }
                    Err(e) => {
                        vlog!(VerbosityLevel::Debug, "Key decrypt error {} -> {}: {}", sender_id, receiver_id, e);
                    }
                }
            }
            
            // Store new outbound session --- do this after all receivers have decrypted to maximize chances of successful distribution before any sender starts using the new session.
            self.sender_sessions.insert(sender_id.clone(), new_megolm_outbound);
            self.message_count_per_sender.insert(sender_id.clone(), 0);
        }

        // During real rotations (not initial setup), force an asymmetric PQC ratchet step
        // on every inbound session. Sessions with an established peer key execute KEM
        // immediately; sessions without one will execute KEM on the next message exchange.
        if is_rotation {
            let mut sessions_forced = 0;
            let mut sessions_lazy = 0;
            let mut sessions_classical = 0;
            
            // Collect all pairs (sender_id, receiver_id, outbound_session)
            let mut session_list: Vec<(String, String)> = Vec::new();
            for (sender_id, member) in self.members.iter() {
                for receiver_id in member.olm_sessions.keys() {
                    session_list.push((sender_id.clone(), receiver_id.clone()));
                }
            }
            
            for (sender_id, receiver_id) in session_list {
                // Force the ratchet on the INBOUND session of the receiver: inbound sessions
                // have a peer key established after receiving the first message, whereas
                // outbound sessions only acquire one after a reply arrives.
                // The pending KEM ciphertext is stored in OlmSessionPair so the outbound
                // session can include it in the next message it sends.
                if let Some(receiver) = self.members.get_mut(&receiver_id) {
                    if let Some(olm_pair) = receiver.olm_sessions.get_mut(&sender_id) {
                        if let Some(ref mut inbound_session) = olm_pair.inbound {
                            let has_peer_key = inbound_session.has_peer_key();
                            
                            match inbound_session.force_asymmetric_ratchet_advance() {
                                Ok(()) => {
                                    if inbound_session.is_pqc_enabled() {
                                        if has_peer_key {
                                            if let Some(pending_kem) = inbound_session.hybrid_session.take_pending_kem_ciphertext() {
                                                olm_pair.pending_kem_for_outbound = Some(pending_kem.clone());
                                                vlog!(VerbosityLevel::Debug, "Forced ratchet {} <- {}: KEM ({} bytes)", 
                                                     receiver_id, sender_id, pending_kem.len());
                                            }
                                            sessions_forced += 1;
                                        } else {
                                            sessions_lazy += 1;
                                            vlog!(VerbosityLevel::Debug, "Forced ratchet {} <- {}: no peer key yet", 
                                                 receiver_id, sender_id);
                                        }
                                    } else {
                                        sessions_classical += 1;
                                    }
                                }
                                Err(e) => {
                                    vlog!(VerbosityLevel::Debug, "Forced ratchet error {} <- {}: {:?}", 
                                         receiver_id, sender_id, e);
                                }
                            }
                        }
                    }
                }
            }
            
            vlog!(VerbosityLevel::Debug, "   -  asymmetric advance complete:");
            vlog!(VerbosityLevel::Debug, "      └─ PQC sessions forced: {} (KEM executed, peer_key established)", sessions_forced);
            vlog!(VerbosityLevel::Debug, "      └─ PQC sessions lazy: {} (KEM deferred until first use)", sessions_lazy);
            vlog!(VerbosityLevel::Debug, "      └─ classical sessions: {} (no PQC)", sessions_classical);
            
            self.num_asymmetric_advances += sessions_forced;
            
            if sessions_forced > 0 {
                vlog!(VerbosityLevel::Normal, "Forced ratchet: {} sessions executed KEM", sessions_forced);
            } else if sessions_lazy > 0 {
                vlog!(VerbosityLevel::Normal, "Forced ratchet inactive: {} sessions without peer key", sessions_lazy);
            }
            let _ = sessions_classical;
        } else {
            vlog!(VerbosityLevel::Debug, "Initial setup: skipping forced ratchet");
        }

        let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
        self.time_rotation_ms += elapsed;
        
        self.current_session_stats.creation_time_ms = 0.0;
        self.current_session_stats.distribution_time_ms = elapsed;

        self.in_rotation_phase = false;

        Ok(())
    }

    /// Rotates all sessions (Olm + Megolm). Use after membership changes.
    /// For periodic rotations prefer `rotate_megolm_only`.
    pub(crate) fn rotate_all_sessions(&mut self, reason: String) -> Result<()> {
        vlog!(VerbosityLevel::Verbose, "Rotating all sessions (reason: {})", reason);
        
        if !self.sender_sessions.is_empty() {
            self.session_history.push(std::mem::take(&mut self.current_session_stats));
            self.rotation_count += 1;
        }

        self.message_count = 0;
        self.message_count_per_sender.clear();
        self.session_start_time = std::time::Instant::now();

        self.sender_sessions.clear();
        self.create_sessions()
    }

    /// Ensures an outbound Olm session exists from `sender_id` to `receiver_id`.
    /// The inbound session is created lazily on first decrypt.
    pub(crate) fn ensure_olm_session(&mut self, sender_id: &str, receiver_id: &str) -> Result<()> {
        let needs_creation = if let Some(sender) = self.members.get(sender_id) {
            if let Some(pair) = sender.olm_sessions.get(receiver_id) {
                !pair.has_outbound()
            } else {
                true
            }
        } else {
            return Err(anyhow::anyhow!("Sender {} not found", sender_id));
        };

        if needs_creation {
            let (outbound_session, init_message_opt) = self.create_outbound_olm_session_only(sender_id, receiver_id)?;
            
            if let Some(init_msg) = init_message_opt {
                if let Some(receiver) = self.members.get_mut(receiver_id) {
                    receiver.crypto.set_pqxdh_init_message(init_msg);
                }
            }
            
            if let Some(sender) = self.members.get_mut(sender_id) {
                let pair = sender.olm_sessions.entry(receiver_id.to_string())
                    .or_insert_with(OlmSessionPair::new);
                pair.outbound = Some(outbound_session);
            }
        }

        Ok(())
    }
    pub(crate) fn should_rotate(&self) -> Option<String> {
        if self.sender_sessions.is_empty() {
            return None;
        }

        if self.message_count >= self.rotation_config.max_messages {
            return Some(format!("message_limit:{}", self.message_count));
        }

        let session_age_ms = self.session_start_time.elapsed().as_millis() as u64;
        if session_age_ms >= self.rotation_config.max_age_ms {
            return Some(format!("time_limit:{}ms", session_age_ms));
        }

        None
    }
}
