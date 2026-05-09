// Abstração de Sala Matrix para Experimentos PQC
//
// Este módulo implementa uma abstração de sala Matrix para experimentos
// comparativos, simulando comunicação em grupo e distribuição de chaves
// Megolm via canais Olm híbridos versus clássicos.

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

/// Sala Matrix experimental com suporte PQC
/// 
/// Sempre usa modo multi-sender (qualquer membro pode enviar mensagens).
/// O padrão de tráfego determina a frequência de rekeying do Double Ratchet.
pub struct MatrixRoom {
    /// ID da sala
    pub room_id: String,
    /// Modo criptográfico (híbrido ou clássico)
    pub crypto_mode: CryptoMode,
    /// Membros da sala
    pub members: HashMap<UserId, RoomMember>,
    /// Sessões Megolm outbound por sender (cada membro tem sua própria sessão)
    pub sender_sessions: HashMap<UserId, MegolmOutbound>,
    /// Política de rotação (Paranoid/Balanced/Relaxed)
    pub rotation_policy: RotationPolicy,
    /// Configuração de rotação
    pub rotation_config: RotationConfig,
    /// Estatísticas da sessão atual
    pub current_session_stats: MegolmSessionStats,
    /// Histórico de sessões
    pub session_history: Vec<MegolmSessionStats>,
    /// Contador de rotações de sessão Megolm
    pub rotation_count: usize,
    /// Contador de mensagens na sessão atual (global)
    pub message_count: usize,
    /// Contador de mensagens por sender
    pub message_count_per_sender: HashMap<UserId, usize>,
    /// Timestamp da criação da sessão atual
    pub session_start_time: std::time::Instant,
    /// Rastreamento de largura de banda (bytes)
    pub bandwidth_key_exchange: usize,     // Public keys (identity + PQXDH) - BUNDLE COMPLETO
    pub bandwidth_session_distribution: usize,  // Megolm session keys via Olm
    pub bandwidth_rekeying: usize,         // Double Ratchet PQC (troca de direção)
    pub bandwidth_messages: usize,         // Megolm encrypted messages
    
    // ============================================================================
    // MÉTRICAS REFINADAS - Duas Comparações Independentes
    // ============================================================================
    
    /// COMPARAÇÃO 1: Overhead PQC (Clássico vs Híbrido)
    /// Apenas controle (acordo + distribuição + rotação) - Megolm messages EXCLUÍDAS
    
    // ========== 1.1) ACORDO (PQXDH/3DH Handshake) ==========
    // PROTOCOLO COMPLETO (medição via PreKeyMessage)
    pub bandwidth_agreement: usize,             // Total do protocolo (Bundle + PreKeyMessage)
    pub bandwidth_agreement_classical: usize,   // Componentes clássicos do protocolo
    pub bandwidth_agreement_pqc: usize,         // Componentes PQC do protocolo
    
    // PRIMITIVAS ISOLADAS (medição direta dos componentes criptográficos)
    pub bandwidth_agreement_primitives_identity_keys: usize,  // Curve25519 + Ed25519 (64B)
    pub bandwidth_agreement_primitives_otk: usize,            // One-Time Key (32B)
    pub bandwidth_agreement_primitives_kyber1024: usize,      // Public key Kyber-1024 (~1568B)
    pub bandwidth_agreement_primitives_prekey_overhead: usize, // Overhead de serialização (JSON, base64, etc)
    
    // ========== 1.2) DISTRIBUIÇÃO INICIAL ==========
    // PROTOCOLO COMPLETO (mensagens Olm com session key Megolm)
    pub bandwidth_initial_distribution: usize,          // Total do protocolo
    pub bandwidth_initial_distribution_classical: usize, // Componentes clássicos
    pub bandwidth_initial_distribution_pqc: usize,       // Componentes PQC
    
    // PRIMITIVAS ISOLADAS
    pub bandwidth_initial_distribution_primitives_megolm_key: usize,  // Chave Megolm (308B)
    pub bandwidth_initial_distribution_primitives_ratchet_key: usize, // Ratchet key (32B ou 1219B)
    pub bandwidth_initial_distribution_primitives_kem_ct: usize,      // KEM ciphertext (~1088B)
    pub bandwidth_initial_distribution_primitives_olm_overhead: usize, // Overhead Olm message
    
    // ========== 1.3) ROTAÇÃO ==========
    // PROTOCOLO COMPLETO (redistribuição de nova session key)
    pub bandwidth_rotation: usize,              // Total do protocolo
    pub bandwidth_rotation_classical: usize,    // Componentes clássicos
    pub bandwidth_rotation_pqc: usize,          // Componentes PQC
    
    // PRIMITIVAS ISOLADAS
    pub bandwidth_rotation_primitives_megolm_key: usize,     // Nova chave Megolm (308B)
    pub bandwidth_rotation_primitives_ratchet_key: usize,    // Ratchet key atualizada
    pub bandwidth_rotation_primitives_kem_ct: usize,         // KEM ciphertext
    pub bandwidth_rotation_primitives_olm_overhead: usize,   // Overhead Olm message
    
    pub bandwidth_megolm_messages: usize,       // 1.4) Mensagens Megolm (NÃO CONTA PARA PQC)
    
    /// COMPARAÇÃO 2: Controle vs Dados
    pub bandwidth_control_plane: usize,         // Acordo + Distribuição + Rotação (TOTAL)
    pub bandwidth_data_plane: usize,            // Mensagens Megolm cifradas (TOTAL)
    
    /// Rastreamento de tempo (milissegundos) - ALINHADO COM LARGURA DE BANDA
    pub time_agreement_ms: f64,              // Agreement: estabelecer TODAS as sessões Olm (PQXDH/3DH)
    pub time_initial_distribution_ms: f64,   // Initial Distribution: distribuir Megolm key via Olm
    pub time_rotation_ms: f64,               // Rotation: redistribuir nova Megolm key via Olm
    pub time_messages_ms: f64,               // Messages: encriptação/decriptação Megolm
    /// Flag para indicar se estamos na fase de setup (create_sessions)
    pub in_setup_phase: bool,
    /// Flag para indicar se estamos na fase de rotação (rotate_megolm)
    pub in_rotation_phase: bool,
    
    /// ACTIVE SENDERS: Lista de senders que devem ter suas métricas contabilizadas
    /// Sessões Olm são criadas eagerly (N×(N-1) para PQXDH), mas só contabilizamos
    /// bandwidth/tempo das que pertencem aos senders ativos (experiência do usuário)
    pub active_senders: std::collections::HashSet<String>,
    
    /// Rastreamento de avanços do Double Ratchet
    pub num_ratchet_advances: usize,       // Total de avanços (simétricos + assimétricos)
    pub num_asymmetric_advances: usize,    // Apenas mudanças de direção (Inactive↔Active)
    
    /// CONTADOR DE MENSAGENS DE ROTAÇÃO (para validar bandwidth_rotation)
    pub num_rotation_messages: usize,      // Mensagens enviadas durante rotação (real, não estimado)
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
            
            // COMPARAÇÃO 1: Overhead PQC - Protocolo completo
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
            
            // COMPARAÇÃO 2: Controle vs Dados
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

    /// Cria sala híbrida com política específica
    pub fn new_hybrid(room_id: String, policy: RotationPolicy) -> Self {
        Self::new(room_id, CryptoMode::Hybrid, policy)
    }

    /// Cria sala clássica com política específica
    pub fn new_classical(room_id: String, policy: RotationPolicy) -> Self {
        Self::new(room_id, CryptoMode::Classical, policy)
    }

    /// Adiciona membro à sala
    pub fn add_member(&mut self, user_id: UserId) -> Result<()> {
        if self.members.contains_key(&user_id) {
            return Ok(()); // Já é membro
        }

        let member = RoomMember::new(user_id.clone(), self.crypto_mode.clone());
        self.members.insert(user_id.clone(), member);

        // LAZY SESSION: Sessões Olm serão criadas sob demanda via ensure_olm_session()
        // quando um sender precisar enviar mensagem para este membro.
        // A init_message PQXDH é transmitida automaticamente durante criação da sessão.
        // Não criamos sessões eagerly - apenas quando necessário para envio real.
        vlog!(VerbosityLevel::Debug, "   - Membro {} adicionado (sessões Olm criadas sob demanda)", user_id);
        
        // Rotacionar chaves se configurado (cria novas sessões Megolm para todos)
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

    /// Remove membro da sala
    pub fn remove_member(&mut self, user_id: &str) -> Result<()> {
        if self.members.remove(user_id).is_none() {
            return Ok(()); // Não era membro
        }

        // Remover sessões Megolm do membro removido
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
