// Abstração de Sala Matrix para Experimentos PQC
//
// Este módulo implementa uma abstração de sala Matrix para experimentos
// comparativos, simulando comunicação em grupo e distribuição de chaves
// Megolm via canais Olm híbridos versus clássicos.

use std::collections::HashMap;
use anyhow::{Result, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::core::{
    crypto::{CryptoProvider, CryptoError, KeyAgreementStats, OlmSessionHandle, MegolmOutbound, MegolmInbound, IdentityKeysExport, OneTimeKeyExport},
};
use crate::core::providers::hybrid::VodoCryptoHybrid;
use crate::core::providers::classical::VodoCrypto;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;

/// Identificador único de usuário Matrix
pub type UserId = String;

/// Política de rotação de chaves Megolm (presets para experimentos)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RotationPolicy {
    /// Paranoid: Máxima segurança (rotação muito frequente)
    /// - 25 mensagens ou 12 horas
    /// - Rotação em qualquer mudança de membros
    /// - Uso: Ambientes de altíssima segurança
    Paranoid,
    
    /// PQ3: Inspirado no Apple PQ3 (rotação frequente)
    /// - 50 mensagens ou 1 dia
    /// - Rotação em mudanças de membros
    /// - Uso: Referência de implementação PQC em produção
    PQ3,
    
    /// Balanced: Equilíbrio segurança/performance (padrão Matrix)
    /// - 100 mensagens ou 7 dias
    /// - Rotação em mudanças de membros
    /// - Uso: Recomendado para uso geral
    Balanced,
    
    /// Relaxed: Desempenho prioritário (rotação espaçada)
    /// - 250 mensagens ou 30 dias
    /// - Sem rotação automática em mudanças de membros
    /// - Uso: Ambientes com restrições de banda/processamento
    Relaxed,
}

impl RotationPolicy {
    /// Converte política para configuração concreta
    pub fn to_config(&self) -> RotationConfig {
        match self {
            RotationPolicy::Paranoid => RotationConfig {
                max_messages: 25,
                max_age_ms: 12 * 3600 * 1000, // 12 horas
                rotate_on_member_join: true,
                rotate_on_member_leave: true,
            },
            RotationPolicy::PQ3 => RotationConfig {
                max_messages: 50,
                max_age_ms: 24 * 3600 * 1000, // 1 dia
                rotate_on_member_join: true,
                rotate_on_member_leave: true,
            },
            RotationPolicy::Balanced => RotationConfig {
                max_messages: 100,
                max_age_ms: 7 * 24 * 3600 * 1000, // 7 dias
                rotate_on_member_join: true,
                rotate_on_member_leave: true,
            },
            RotationPolicy::Relaxed => RotationConfig {
                max_messages: 250,
                max_age_ms: 30 * 24 * 3600 * 1000, // 30 dias
                rotate_on_member_join: false,
                rotate_on_member_leave: false,
            },
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        RotationPolicy::Balanced
    }
}

/// Configuração de rotação de chaves Megolm
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Rotação a cada N mensagens
    pub max_messages: usize,
    /// Rotação a cada N milissegundos (simulando dias)
    pub max_age_ms: u64,
    /// Rotação quando novo membro entra
    pub rotate_on_member_join: bool,
    /// Rotação quando membro sai
    #[allow(dead_code)]
    pub rotate_on_member_leave: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        RotationPolicy::Balanced.to_config()
    }
}

/// Modo criptográfico da sala
#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub enum CryptoMode {
    /// Modo híbrido com CRYSTALS-Kyber + X25519
    Hybrid,
    /// Modo clássico apenas com X25519  
    Classical,
}

/// Provedor criptográfico unificado
pub enum CryptoWrapper {
    Hybrid(VodoCryptoHybrid),
    Classical(VodoCrypto),
}

impl CryptoWrapper {
    pub fn new_hybrid() -> Self {
        Self::Hybrid(CryptoProvider::account_new())
    }

    pub fn new_classical() -> Self {
        Self::Classical(CryptoProvider::account_new())
    }

    pub fn upload_identity_keys(&self) -> IdentityKeysExport {
        match self {
            Self::Hybrid(crypto) => crypto.upload_identity_keys(),
            Self::Classical(crypto) => crypto.upload_identity_keys(),
        }
    }

    pub fn megolm_create_outbound(&mut self) -> MegolmOutbound {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_create_outbound(),
            Self::Classical(crypto) => crypto.megolm_create_outbound(),
        }
    }

    pub fn megolm_export_inbound(&mut self, outbound: &MegolmOutbound) -> String {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_export_inbound(outbound),
            Self::Classical(crypto) => crypto.megolm_export_inbound(outbound),
        }
    }

    pub fn megolm_import_inbound(&mut self, session_key: &str) -> MegolmInbound {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_import_inbound(session_key),
            Self::Classical(crypto) => crypto.megolm_import_inbound(session_key),
        }
    }

    pub fn megolm_encrypt(&mut self, session: &mut MegolmOutbound, plaintext: &[u8]) -> String {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_encrypt(session, plaintext),
            Self::Classical(crypto) => crypto.megolm_encrypt(session, plaintext),
        }
    }

    pub fn megolm_decrypt(&mut self, session: &mut MegolmInbound, ciphertext: &str) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Hybrid(crypto) => crypto.megolm_decrypt(session, ciphertext),
            Self::Classical(crypto) => crypto.megolm_decrypt(session, ciphertext),
        }
    }

    pub fn set_pqxdh_init_message(&mut self, init_message: crate::core::pqxdh::MatrixPqxdhInitMessage) {
        match self {
            Self::Hybrid(crypto) => crypto.set_pqxdh_init_message(init_message),
            Self::Classical(crypto) => crypto.set_pqxdh_init_message(init_message),
        }
    }

    pub fn olm_encrypt(&mut self, session: &mut OlmSessionHandle, plaintext: &[u8]) -> String {
        match self {
            Self::Hybrid(crypto) => crypto.olm_encrypt(session, plaintext),
            Self::Classical(crypto) => crypto.olm_encrypt(session, plaintext),
        }
    }

    pub fn olm_decrypt(&mut self, session: &mut OlmSessionHandle, ciphertext: &str) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Hybrid(crypto) => crypto.olm_decrypt(session, ciphertext),
            Self::Classical(crypto) => crypto.olm_decrypt(session, ciphertext),
        }
    }

    pub fn generate_one_time_keys(&mut self, count: usize) -> Vec<OneTimeKeyExport> {
        match self {
            Self::Hybrid(crypto) => crypto.generate_one_time_keys(count),
            Self::Classical(crypto) => crypto.generate_one_time_keys(count),
        }
    }

    pub fn mark_keys_published(&mut self) {
        match self {
            Self::Hybrid(crypto) => crypto.mark_keys_published(),
            Self::Classical(crypto) => crypto.mark_keys_published(),
        }
    }

    pub fn create_inbound_session(&mut self, their_curve25519: &str, prekey_message_b64: &str) -> Result<(OlmSessionHandle, Vec<u8>), CryptoError> {
        match self {
            Self::Hybrid(crypto) => crypto.create_inbound_session(their_curve25519, prekey_message_b64),
            Self::Classical(crypto) => crypto.create_inbound_session(their_curve25519, prekey_message_b64),
        }
    }

    // Métodos específicos PQXDH para modo híbrido
    pub fn export_pqxdh_public_keys(&self) -> Option<serde_json::Value> {
        if let Self::Hybrid(crypto) = self {
            Some(crypto.export_pqxdh_public_keys())
        } else {
            None
        }
    }

}

/// Sessões Olm bidirecionais com outro membro
pub struct OlmSessionPair {
    /// Sessão outbound para ENVIAR mensagens (criada com create_outbound_session)
    pub outbound: Option<OlmSessionHandle>,
    /// Sessão inbound para RECEBER mensagens (criada com create_inbound_session)
    pub inbound: Option<OlmSessionHandle>,
    /// KEM ciphertext pendente gerado por forced_ratchet no INBOUND para ser usado pelo OUTBOUND
    /// Compartilhado entre inbound/outbound do mesmo par para que mensagens enviadas
    /// incluam o KEM ciphertext gerado pelo forced_ratchet
    pub pending_kem_for_outbound: Option<Vec<u8>>,
}

impl OlmSessionPair {
    pub fn new() -> Self {
        Self {
            outbound: None,
            inbound: None,
            pending_kem_for_outbound: None,
        }
    }
    
    /// Verifica se tem sessão outbound estabelecida
    pub fn has_outbound(&self) -> bool {
        self.outbound.is_some()
    }
    
    /// Obtém sessão outbound mutável para enviar
    pub fn get_outbound_mut(&mut self) -> Option<&mut OlmSessionHandle> {
        self.outbound.as_mut()
    }
    
    /// Obtém sessão inbound mutável para receber
    pub fn get_inbound_mut(&mut self) -> Option<&mut OlmSessionHandle> {
        self.inbound.as_mut()
    }
}

/// Membro de uma sala Matrix
pub struct RoomMember {
    /// ID do usuário Matrix
    #[allow(dead_code)]
    pub user_id: UserId,
    /// Provedor criptográfico (híbrido ou clássico)
    pub crypto: CryptoWrapper,
    /// Sessões Olm com outros membros (outbound + inbound para cada peer)
    pub olm_sessions: HashMap<UserId, OlmSessionPair>,
    /// Sessão Megolm inbound atual (para descriptografia)
    pub megolm_inbound: Option<MegolmInbound>,
}

impl RoomMember {
    pub fn new_hybrid(user_id: UserId) -> Self {
        Self {
            user_id,
            crypto: CryptoWrapper::new_hybrid(),
            olm_sessions: HashMap::new(),
            megolm_inbound: None,
        }
    }

    pub fn new_classical(user_id: UserId) -> Self {
        Self {
            user_id,
            crypto: CryptoWrapper::new_classical(),
            olm_sessions: HashMap::new(),
            megolm_inbound: None,
        }
    }

    pub fn new(user_id: UserId, mode: CryptoMode) -> Self {
        match mode {
            CryptoMode::Hybrid => Self::new_hybrid(user_id),
            CryptoMode::Classical => Self::new_classical(user_id),
        }
    }


}

/// Estatísticas de uma sessão Megolm
#[derive(Debug, Default, Clone)]
pub struct MegolmSessionStats {
    pub creation_time_ms: f64,
    pub distribution_time_ms: f64,
    pub messages_encrypted: usize,
    pub total_bytes_encrypted: usize,
    #[allow(dead_code)]
    pub key_agreement_stats: KeyAgreementStats,
}

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
    // PROTOCOLO COMPLETO (wire protocol - medição REAL via PreKeyMessage)
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

    /// Cria sessão Olm OUTBOUND sem gerar PreKeyMessage antecipadamente
    /// PreKeyMessage será gerada AUTOMATICAMENTE na primeira encrypt()
    /// 
    /// # Retorno
    /// Tupla (OlmSessionHandle, Option<MatrixPqxdhInitMessage>)
    fn create_outbound_olm_session_only(&mut self, sender_id: &str, receiver_id: &str) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>)> {
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
            let mut batch_encrypted_keys: Vec<(String, String)> = Vec::new();
            
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
        
        let mut warmup_messages: Vec<(String, String, String)> = Vec::new(); // (sender, receiver, encrypted)
        let mut warmup_sent = 0;
        let mut warmup_received = 0;
        
        // Fase 0: Coletar pares (sender, receiver) onde sessão outbound já existe
        let mut session_pairs: Vec<(String, String)> = Vec::new();
        for (sender_id, sender) in self.members.iter() {
            for receiver_id in sender.olm_sessions.keys() {
                if sender_id != receiver_id {
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
    
    /// Rotaciona APENAS sessões Megolm dos senders ativos, preservando sessões Olm existentes
    /// Método otimizado conforme recomendação para reduzir overhead de rotação
    fn rotate_megolm_only(&mut self, reason: String) -> Result<()> {
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
            let mut batch_encrypted_keys: Vec<(String, String)> = Vec::new();
            
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
    fn rotate_all_sessions(&mut self, reason: String) -> Result<()> {
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
    fn ensure_olm_session(&mut self, sender_id: &str, receiver_id: &str) -> Result<()> {
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

    /// Criptografa chave Megolm via canal Olm no modo multi-sender
    fn encrypt_megolm_key_via_olm_multi_sender(&mut self, sender_id: &str, session_key: &str, receiver_id: &str) -> Result<String> {
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

        let encrypted_key = sender.crypto.olm_encrypt(olm_session, session_key.as_bytes());

        // LOG DETALHADO: Breakdown da mensagem
        vlog!(VerbosityLevel::Debug, "       [ENCRYPT_BREAKDOWN] {} -> {}:", sender_id, receiver_id);
        vlog!(VerbosityLevel::Debug, "         └─ Total message size: {} bytes", encrypted_key.len());
        vlog!(VerbosityLevel::Debug, "         └─ Session key payload: {} bytes", session_key.len());
        vlog!(VerbosityLevel::Debug, "         └─ Is PQC enabled: {}", olm_session.is_pqc_enabled());
        vlog!(VerbosityLevel::Debug, "         └─ Has peer key: {}", olm_session.has_peer_key());
        
        // Tentar decodificar JSON para ver tipo de mensagem e breakdown detalhado
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&encrypted_key) {
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
                                            vlog!(VerbosityLevel::Debug, "         └─ [BODY PARSE] KEM ciphertext: {} bytes 🔥", kem_ct_len);
                                            
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
        
        // ============================================================================
        // DETECTAR PreKeyMessage (type 0) = AGREEMENT PHASE
        // ============================================================================
        // PreKeyMessage acontece na PRIMEIRA encrypt entre dois peers (3DH/PQXDH handshake)
        // É a medição REAL do Agreement protocol
        let mut is_prekey_message = false;
        
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&encrypted_key) {
            if let Some(msg_type) = json_val.get("type").and_then(|t| t.as_u64()) {
                if msg_type == 0 {
                    is_prekey_message = true;
                    
                    // PROTOCOLO COMPLETO: Agreement (PreKeyMessage real)
                    self.bandwidth_agreement += encrypted_key.len();
                    self.bandwidth_agreement_classical += classical_bytes;
                    self.bandwidth_agreement_pqc += pqc_bytes;
                    
                    // Calcular overhead de serialização
                    let primitives_total = self.bandwidth_agreement_primitives_identity_keys
                                         + self.bandwidth_agreement_primitives_otk
                                         + self.bandwidth_agreement_primitives_kyber1024;
                    
                    if encrypted_key.len() > primitives_total {
                        self.bandwidth_agreement_primitives_prekey_overhead += 
                            encrypted_key.len() - primitives_total;
                    }
                    
                    vlog!(VerbosityLevel::Normal,
                          "      [AGREEMENT] PreKeyMessage {} -> {}: {} bytes (classical={}, pqc={}, primitives={})",
                          sender_id, receiver_id, encrypted_key.len(), classical_bytes, pqc_bytes, primitives_total);
                }
            }
        }
        
        let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
        
        // PreKeyMessage (type 0) NÃO deve ser contada como distribuição, apenas como Agreement
        if is_prekey_message {
            // Já foi contada em bandwidth_agreement acima
            // Não adicionar em nenhuma outra categoria
            vlog!(VerbosityLevel::Debug, 
                  "         └─PreKeyMessage detectada: excluída de outras categorias");
        } else if self.in_setup_phase {
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
            
            // Parsear para extrair ratchet key e KEM CT
            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&encrypted_key) {
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
                                    } else if pqc_enabled == 0 {
                                        // Classical: ratchet key 32B
                                        let classical_ratchet_size = 32;
                                        self.bandwidth_initial_distribution_primitives_ratchet_key += classical_ratchet_size;
                                        
                                        let primitives_sum = megolm_key_size + classical_ratchet_size;
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
            
            // Para extrair ratchet key e KEM CT, precisamos parsear a mensagem
            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&encrypted_key) {
                if let Some(body) = json_val.get("body").and_then(|b| b.as_str()) {
                    if let Ok(decoded) = B64.decode(body) {
                        // Parsear estrutura binária
                        // Formato: [1B version][1B type][4B classic_len][classic_bytes][4B msg_index][1B pqc_enabled]
                        //          [4B ratchet_key_len][ratchet_key][4B kem_ct_len][kem_ct]
                        
                        if decoded.len() >= 19 {  // Mínimo para ter headers
                            let mut offset = 0;
                            offset += 1; // version
                            offset += 1; // type
                            
                            // Classic length
                            if decoded.len() >= offset + 4 {
                                let classic_len = u32::from_le_bytes([
                                    decoded[offset], decoded[offset+1], 
                                    decoded[offset+2], decoded[offset+3]
                                ]) as usize;
                                offset += 4;
                                
                                // Skip classic payload (Megolm key)
                                if decoded.len() >= offset + classic_len + 5 {
                                    offset += classic_len;
                                    offset += 4; // msg_index
                                    
                                    let pqc_enabled = decoded[offset];
                                    offset += 1;
                                    
                                    if pqc_enabled == 1 && decoded.len() >= offset + 4 {
                                        // Ratchet key length
                                        let ratchet_key_len = u32::from_le_bytes([
                                            decoded[offset], decoded[offset+1],
                                            decoded[offset+2], decoded[offset+3]
                                        ]) as usize;
                                        offset += 4;
                                        
                                        self.bandwidth_rotation_primitives_ratchet_key += ratchet_key_len;
                                        
                                        // KEM ciphertext length
                                        if decoded.len() >= offset + ratchet_key_len + 4 {
                                            offset += ratchet_key_len;
                                            
                                            let kem_ct_len = u32::from_le_bytes([
                                                decoded[offset], decoded[offset+1],
                                                decoded[offset+2], decoded[offset+3]
                                            ]) as usize;
                                            
                                            self.bandwidth_rotation_primitives_kem_ct += kem_ct_len;
                                            
                                            // Overhead Olm = total - (megolm + ratchet + kem)
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
                                    } else if pqc_enabled == 0 {
                                        // Classical mode: apenas ratchet key (32B)
                                        let classical_ratchet_size = 32;
                                        self.bandwidth_rotation_primitives_ratchet_key += classical_ratchet_size;
                                        
                                        // Overhead Olm
                                        let primitives_sum = megolm_key_size + classical_ratchet_size;
                                        if encrypted_key.len() > primitives_sum {
                                            self.bandwidth_rotation_primitives_olm_overhead += 
                                                encrypted_key.len() - primitives_sum;
                                        }
                                        
                                        vlog!(VerbosityLevel::Debug,
                                              "         └─[PRIMITIVES CLASSICAL] Megolm={}B, Ratchet={}B, Overhead={}B",
                                              megolm_key_size, classical_ratchet_size,
                                              encrypted_key.len() - primitives_sum);
                                    }
                                }
                            }
                        }
                    }
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
    fn decrypt_megolm_key_via_olm_multi_sender(&mut self, encrypted_key: &str, receiver_id: &str, sender_id: &str) -> Result<String> {
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
                        
                        return String::from_utf8(decrypted_bytes)
                            .map_err(|e| anyhow::anyhow!("Erro ao converter chave descriptografada: {}", e));
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
                
                String::from_utf8(decrypted_bytes)
                    .map_err(|e| anyhow::anyhow!("Erro ao converter chave descriptografada: {}", e))
            }
            Err(e) => {
                Err(anyhow::anyhow!("Falha na descriptografia de {} para {}: {}", sender_id, receiver_id, e))
            }
        }
    }

    /// Verifica se rotação é necessária
    fn should_rotate(&self) -> Option<String> {
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

    /// Envia mensagem na sala (com rotação automática)
    pub fn send_message(&mut self, sender_id: &str, content: &[u8]) -> Result<String> {
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
    pub fn decrypt_message(&mut self, receiver_id: &str, encrypted_message: &str) -> Result<Vec<u8>> {
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
    
    /// Criptografa mensagem simples via Olm (usado para warm-up bidirecional)
    fn encrypt_simple_message(&mut self, sender_id: &str, receiver_id: &str, plaintext: &[u8]) -> Result<String> {
        let sender = self.members.get_mut(sender_id)
            .context("Sender não encontrado")?;
        
        let olm_session_pair = sender.olm_sessions.get_mut(receiver_id)
            .context("Sessão Olm não encontrada")?;
        
        let olm_session = olm_session_pair.get_outbound_mut()
            .context("Sessão Olm outbound não encontrada")?;

        Ok(sender.crypto.olm_encrypt(olm_session, plaintext))
    }
    
    /// Descriptografa mensagem simples via Olm (usado para warm-up bidirecional)
    fn decrypt_simple_message(&mut self, encrypted: &str, receiver_id: &str, sender_id: &str) -> Result<Vec<u8>> {
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
    
    /// Extrai breakdown REAL de uma mensagem Olm criptografada
    /// Retorna: (classical_bytes, pqc_bytes)
    fn extract_message_breakdown(encrypted_message: &str, crypto_mode: &CryptoMode) -> (usize, usize) {
        // Para Classical: toda mensagem é clássica
        if *crypto_mode == CryptoMode::Classical {
            return (encrypted_message.len(), 0);
        }
        
        vlog!(VerbosityLevel::Debug, "         └─[EXTRACT] Analisando mensagem de {} bytes", encrypted_message.len());
        
        // Para Hybrid: tentar decodificar o JSON e extrair componentes reais
        // Formato esperado: {"type":X,"body":"base64_payload"}
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(encrypted_message) {
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