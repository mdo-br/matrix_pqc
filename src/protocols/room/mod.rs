//! Matrix room abstraction for PQC experiments.
//!
//! Implements an experimental Matrix room for comparative studies, simulating
//! group communication and Megolm key distribution over hybrid vs classical Olm channels.

pub mod rotation;
pub mod crypto_backend;
pub mod member;
pub mod session_mgmt;
pub mod rotation_impl;
pub mod crypto_impl;
pub mod messaging;

pub use rotation::{RotationPolicy, RotationConfig};
pub use crypto_backend::{CryptoMode, CryptoWrapper};
pub use member::{UserId, OlmSessionPair, RoomMember, MegolmSessionStats};

use std::collections::HashMap;
use anyhow::{Result};
use crate::core::crypto::MegolmOutbound;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;

/// Experimental Matrix room with PQC support.
///
/// Always operates in multi-sender mode (any member may send messages).
/// The traffic pattern determines the Double Ratchet rekeying frequency.
pub struct MatrixRoom {
    /// Room identifier.
    pub room_id: String,
    /// Cryptographic mode (hybrid or classical).
    pub crypto_mode: CryptoMode,
    /// Room members.
    pub members: HashMap<UserId, RoomMember>,
    /// Outbound Megolm sessions per sender (each member owns one).
    pub sender_sessions: HashMap<UserId, MegolmOutbound>,
    /// Key rotation policy (Paranoid/Balanced/Relaxed).
    pub rotation_policy: RotationPolicy,
    /// Concrete rotation configuration.
    pub rotation_config: RotationConfig,
    /// Statistics for the current session.
    pub current_session_stats: MegolmSessionStats,
    /// History of past sessions.
    pub session_history: Vec<MegolmSessionStats>,
    /// Number of Megolm session rotations.
    pub rotation_count: usize,
    /// Global message counter for the current session.
    pub message_count: usize,
    /// Per-sender message counter.
    pub message_count_per_sender: HashMap<UserId, usize>,
    /// Creation timestamp of the current session.
    pub session_start_time: std::time::Instant,
    /// Bandwidth tracking in bytes.
    pub bandwidth_key_exchange: usize,          // Public keys (identity + PQXDH) — full bundle.
    pub bandwidth_session_distribution: usize,  // Megolm session keys over Olm.
    pub bandwidth_rekeying: usize,              // Double Ratchet PQC (direction change).
    pub bandwidth_messages: usize,              // Megolm encrypted messages.

    // ============================================================================
    // REFINED METRICS — Two independent comparisons
    // ============================================================================

    /// COMPARISON 1: PQC overhead (Classical vs Hybrid).
    /// Control plane only (agreement + distribution + rotation) — Megolm messages excluded.

    // ========== 1.1) AGREEMENT (PQXDH/3DH Handshake) ==========
    // Full protocol (measured via PreKeyMessage).
    pub bandwidth_agreement: usize,             // Total protocol bytes (Bundle + PreKeyMessage).
    pub bandwidth_agreement_classical: usize,   // Classical components.
    pub bandwidth_agreement_pqc: usize,         // PQC components.

    // Isolated primitives (direct measurement of cryptographic components).
    pub bandwidth_agreement_primitives_identity_keys: usize,   // Curve25519 + Ed25519 (64 B).
    pub bandwidth_agreement_primitives_otk: usize,             // One-Time Key (32 B).
    pub bandwidth_agreement_primitives_kyber1024: usize,       // Kyber-1024 public key (~1568 B).
    pub bandwidth_agreement_primitives_prekey_overhead: usize, // Serialisation overhead (JSON, base64…).

    // ========== 1.2) INITIAL DISTRIBUTION ==========
    // Full protocol (Olm messages carrying Megolm session key).
    pub bandwidth_initial_distribution: usize,           // Total protocol bytes.
    pub bandwidth_initial_distribution_classical: usize, // Classical components.
    pub bandwidth_initial_distribution_pqc: usize,       // PQC components.

    // Isolated primitives.
    pub bandwidth_initial_distribution_primitives_megolm_key: usize,  // Megolm key (308 B).
    pub bandwidth_initial_distribution_primitives_ratchet_key: usize, // Ratchet key (32 B or 1219 B).
    pub bandwidth_initial_distribution_primitives_kem_ct: usize,      // KEM ciphertext (~1088 B).
    pub bandwidth_initial_distribution_primitives_olm_overhead: usize, // Olm message overhead.

    // ========== 1.3) ROTATION ==========
    // Full protocol (redistribution of new session key).
    pub bandwidth_rotation: usize,              // Total protocol bytes.
    pub bandwidth_rotation_classical: usize,    // Classical components.
    pub bandwidth_rotation_pqc: usize,          // PQC components.

    // Isolated primitives.
    pub bandwidth_rotation_primitives_megolm_key: usize,     // New Megolm key (308 B).
    pub bandwidth_rotation_primitives_ratchet_key: usize,    // Updated ratchet key.
    pub bandwidth_rotation_primitives_kem_ct: usize,         // KEM ciphertext.
    pub bandwidth_rotation_primitives_olm_overhead: usize,   // Olm message overhead.

    pub bandwidth_megolm_messages: usize,       // 1.4) Megolm messages (NOT counted for PQC overhead).

    /// COMPARISON 2: Control plane vs Data plane.
    pub bandwidth_control_plane: usize,         // Agreement + Distribution + Rotation (total).
    pub bandwidth_data_plane: usize,            // Encrypted Megolm messages (total).

    /// Time tracking in milliseconds — aligned with bandwidth phases.
    pub time_agreement_ms: f64,             // Agreement: establish all Olm sessions (PQXDH/3DH).
    pub time_initial_distribution_ms: f64,  // Initial distribution: send Megolm key over Olm.
    pub time_rotation_ms: f64,              // Rotation: redistribute new Megolm key over Olm.
    pub time_messages_ms: f64,             // Messages: Megolm encryption/decryption.
    /// Flag indicating the setup phase (create_sessions) is active.
    pub in_setup_phase: bool,
    /// Flag indicating the rotation phase (rotate_megolm) is active.
    pub in_rotation_phase: bool,

    /// Active senders whose metrics are counted.
    ///
    /// Olm sessions are created eagerly (N×(N-1) for PQXDH), but only the sessions
    /// belonging to active senders contribute to bandwidth/time measurements.
    pub active_senders: std::collections::HashSet<String>,

    /// Double Ratchet advance tracking.
    pub num_ratchet_advances: usize,    // Total advances (symmetric + asymmetric).
    pub num_asymmetric_advances: usize, // Direction changes only (Inactive↔Active).

    /// Rotation message counter (actual messages sent during rotation, not an estimate).
    pub num_rotation_messages: usize,
}

#[allow(dead_code)]
impl MatrixRoom {
    /// Cria nova sala Matrix experimental (sempre multi-sender)
    pub fn new(room_id: String, crypto_mode: CryptoMode, rotation_policy: RotationPolicy) -> Self {
        let rotation_config = rotation_policy.to_config();
        Self {
            room_id,
            crypto_mode,
            members: HashMap::new(),
            sender_sessions: HashMap::new(),
            rotation_policy,
            rotation_config,
            current_session_stats: MegolmSessionStats::default(),
            session_history: Vec::new(),
            rotation_count: 0,
            message_count: 0,
            message_count_per_sender: HashMap::new(),
            session_start_time: std::time::Instant::now(),
            bandwidth_key_exchange: 0,
            bandwidth_session_distribution: 0,
            bandwidth_rekeying: 0,
            bandwidth_messages: 0,
            
            // COMPARISON 1: PQC overhead — full protocol.
            bandwidth_agreement: 0,
            bandwidth_agreement_classical: 0,
            bandwidth_agreement_pqc: 0,
            bandwidth_initial_distribution: 0,
            bandwidth_initial_distribution_classical: 0,
            bandwidth_initial_distribution_pqc: 0,
            bandwidth_rotation: 0,
            bandwidth_rotation_classical: 0,
            bandwidth_rotation_pqc: 0,
            bandwidth_megolm_messages: 0,
            
            // Primitivas isoladas - Agreement
            bandwidth_agreement_primitives_identity_keys: 0,
            bandwidth_agreement_primitives_otk: 0,
            bandwidth_agreement_primitives_kyber1024: 0,
            bandwidth_agreement_primitives_prekey_overhead: 0,
            
            // Primitivas isoladas - Initial Distribution
            bandwidth_initial_distribution_primitives_megolm_key: 0,
            bandwidth_initial_distribution_primitives_ratchet_key: 0,
            bandwidth_initial_distribution_primitives_kem_ct: 0,
            bandwidth_initial_distribution_primitives_olm_overhead: 0,
            
            // Primitivas isoladas - Rotation
            bandwidth_rotation_primitives_megolm_key: 0,
            bandwidth_rotation_primitives_ratchet_key: 0,
            bandwidth_rotation_primitives_kem_ct: 0,
            bandwidth_rotation_primitives_olm_overhead: 0,
            
            // COMPARISON 2: Control vs. data plane.
            bandwidth_control_plane: 0,
            bandwidth_data_plane: 0,
            
            time_agreement_ms: 0.0,
            time_initial_distribution_ms: 0.0,
            time_rotation_ms: 0.0,
            time_messages_ms: 0.0,
            in_setup_phase: false,
            in_rotation_phase: false,
            active_senders: std::collections::HashSet::new(),
            num_ratchet_advances: 0,
            num_asymmetric_advances: 0,
            num_rotation_messages: 0,
        }
    }

    /// Creates a new hybrid room with the given policy.
    pub fn new_hybrid(room_id: String, policy: RotationPolicy) -> Self {
        Self::new(room_id, CryptoMode::Hybrid, policy)
    }

    /// Creates a new classical room with the given policy.
    pub fn new_classical(room_id: String, policy: RotationPolicy) -> Self {
        Self::new(room_id, CryptoMode::Classical, policy)
    }

    /// Adds a member to the room.
    pub fn add_member(&mut self, user_id: UserId) -> Result<()> {
        if self.members.contains_key(&user_id) {
            return Ok(()); // Already a member.
        }

        let member = RoomMember::new(user_id.clone(), self.crypto_mode.clone());
        self.members.insert(user_id.clone(), member);

        // LAZY SESSION: Olm sessions are created on demand via ensure_olm_session()
        // when a sender needs to send a message to this member.
        // The PQXDH init_message is transmitted automatically during session creation.
        // Sessions are not created eagerly — only when actually needed for sending.
        vlog!(VerbosityLevel::Debug, "   - Membro {} adicionado (sessões Olm criadas sob demanda)", user_id);
        
        // Rotate keys if configured (creates new Megolm sessions for all members).
        if self.rotation_config.rotate_on_member_join && !self.sender_sessions.is_empty() {
            self.rotate_all_sessions(format!("member_join:{}", user_id))?;
        }

        let mode_name = match self.crypto_mode {
            CryptoMode::Hybrid => "HÍBRIDO",
            CryptoMode::Classical => "CLÁSSICO",
        };
        vlog!(VerbosityLevel::Verbose, "   - Membro {} adicionado à sala {} (modo {})", user_id, self.room_id, mode_name);
        Ok(())
    }

    /// Removes a member from the room.
    pub fn remove_member(&mut self, user_id: &str) -> Result<()> {
        if self.members.remove(user_id).is_none() {
            return Ok(()); // Was not a member.
        }

        // Remove Megolm sessions for the removed member.
        self.sender_sessions.remove(user_id);
        self.message_count_per_sender.remove(user_id);

        // Rotacionar chaves se configurado
        if self.rotation_config.rotate_on_member_leave && !self.sender_sessions.is_empty() {
            self.rotate_all_sessions(format!("member_leave:{}", user_id))?;
        }

        vlog!(VerbosityLevel::Verbose, "   - Membro {} removido da sala {}", user_id, self.room_id);
        Ok(())
    }
}
