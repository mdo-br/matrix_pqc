use crate::protocols::room::{MatrixRoom, CryptoMode, RotationPolicy};
use crate::tools::workload::{MessageGenerator, UsageScenario};
use crate::utils::logging::VerbosityLevel;
use crate::{vlog, progress};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Perfil de hardware do dispositivo cliente
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub device_type: String,      // "Mobile", "Desktop", "IoT", "Server"
    pub architecture: String,      // "x86_64", "ARM", "RISC-V"
    pub cpu_model: String,         // Modelo da CPU
    pub cpu_cores: usize,          // Núcleos físicos disponíveis
    pub cpu_freq_mhz: u32,         // Frequência base da CPU
    pub ram_mb: usize,             // Memória RAM total em MB
    pub platform_id: String,       // Identificador único do dispositivo
}

impl HardwareProfile {
    /// Detecta automaticamente o perfil de hardware do sistema
    pub fn detect() -> Self {
        let hostname = hostname::get()
            .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
            .to_string_lossy()
            .to_string();
        
        let cpu_info = sys_info::cpu_speed()
            .map(|speed| format!("{} MHz", speed))
            .unwrap_or_else(|_| "unknown".to_string());
        
        let num_cpus = num_cpus::get();
        
        // Detectar arquitetura
        let architecture = if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else if cfg!(target_arch = "aarch64") {
            "ARM64"
        } else if cfg!(target_arch = "arm") {
            "ARM32"
        } else if cfg!(target_arch = "riscv64") {
            "RISC-V64"
        } else {
            "unknown"
        }.to_string();
        
        // Detectar tipo de dispositivo baseado em características
        let device_type = if num_cpus <= 2 {
            "IoT"
        } else if num_cpus <= 4 {
            "Mobile"
        } else if num_cpus <= 8 {
            "Desktop"
        } else {
            "Server"
        }.to_string();
        
        let ram_mb = sys_info::mem_info()
            .map(|info| (info.total / 1024) as usize)
            .unwrap_or(0);
        
        let cpu_freq_mhz = sys_info::cpu_speed()
            .unwrap_or(0) as u32;
        
        Self {
            device_type,
            architecture,
            cpu_model: cpu_info,
            cpu_cores: num_cpus,
            cpu_freq_mhz,
            ram_mb,
            platform_id: hostname,
        }
    }
}

/// Métricas de política de rotação Megolm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationMetrics {
    pub policy_type: String,           // "Paranoid", "Balanced", "Relaxed", "Custom"
    pub actual_rotations: usize,       // Rotações efetivamente realizadas
    pub messages_between_rotations: Vec<usize>, // Mensagens entre cada rotação
}

impl RotationMetrics {
    pub fn new(policy: &RotationPolicy, actual_rotations: usize) -> Self {
        let policy_type = match policy {
            RotationPolicy::Paranoid => "Paranoid",
            RotationPolicy::PQ3 => "PQ3",
            RotationPolicy::Balanced => "Balanced",
            RotationPolicy::Relaxed => "Relaxed",
            RotationPolicy::Custom => "Custom",
        }.to_string();
        
        Self {
            policy_type,
            actual_rotations, // Usar valor real do contador (MODIFICADO)
            messages_between_rotations: Vec::new(),
        }
    }
}

/// Métricas de largura de banda
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BandwidthMetrics {
    pub kem_handshake_bytes: usize,     // Bytes do handshake KEM
    pub olm_session_bytes: usize,       // Bytes de estabelecimento Olm
    pub megolm_session_bytes: usize,    // Bytes de setup Megolm
    pub message_overhead_bytes: usize,  // Overhead por mensagem
    pub rotation_cost_bytes: usize,     // Custo de cada rotação
    pub total_tx_bytes: usize,          // Total transmitido
    pub total_rx_bytes: usize,          // Total recebido
}

/// Tipo de sala Matrix
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomType {
    DirectMessage,
    SmallGroup,
    MediumGroup,
    LargeChannel,
}

impl RoomType {
    pub fn member_count(&self) -> usize {
        match self {
            RoomType::DirectMessage => 2,
            RoomType::SmallGroup => 7,
            RoomType::MediumGroup => 25,
            RoomType::LargeChannel => 150,
        }
    }
    
    pub fn name(&self) -> &'static str {
        match self {
            RoomType::DirectMessage => "DM",
            RoomType::SmallGroup => "SmallGroup",
            RoomType::MediumGroup => "MediumGroup",
            RoomType::LargeChannel => "LargeChannel",
        }
    }
    
    /// Número de mensagens a enviar por tipo de sala (realista)
    /// 
    /// ATUALIZADO para garantir múltiplas rotações em TODAS as políticas:
    /// - DM: 500 msgs (garante ≥2 rotações Relaxed, diferenciado de SmallGroup)
    /// - SmallGroup: 750 msgs (garante ≥3 rotações Relaxed)
    /// - MediumGroup: 1000 msgs (garante ≥4 rotações Relaxed)
    /// - LargeChannel: 1250 msgs (garante ≥5 rotações Relaxed)
    /// 
    /// NOTA: +1 mensagem de warmup executada antes do loop principal
    /// 
    /// Rotações esperadas por política (incluindo warmup):
    /// - Paranoid (25):  DM=20, Small=30, Medium=40, Large=50
    /// - PQ3 (50):       DM=10, Small=15, Medium=20, Large=25
    /// - Balanced (100): DM=5,  Small=7,  Medium=10, Large=12
    /// - Relaxed (250):  DM=2,  Small=3,  Medium=4,  Large=5
    pub fn messages_to_send(&self) -> usize {
        match self {
            RoomType::DirectMessage => 500,
            RoomType::SmallGroup => 750,
            RoomType::MediumGroup => 1000,
            RoomType::LargeChannel => 1250,
        }
    }
    
    /// Mapeia RoomType para UsageScenario (para MessageGenerator)
    /// Permite gerar mensagens com distribuição realista baseada em estudos empíricos
    pub fn to_usage_scenario(&self) -> UsageScenario {
        match self {
            RoomType::DirectMessage => UsageScenario::SmallChat,
            RoomType::SmallGroup => UsageScenario::SmallChat,
            RoomType::MediumGroup => UsageScenario::MediumGroup,
            RoomType::LargeChannel => UsageScenario::LargeChannel,
        }
    }
}

/// Perfil de uso do usuário
#[derive(Debug, Clone)]
pub struct UserProfile {
    pub user_id: String,
    pub rooms: Vec<(String, RoomType)>,
}

impl UserProfile {
    pub fn typical(user_id: &str) -> Self {
        let mut rooms = Vec::new();
        
        for i in 1..=5 {
            rooms.push((format!("!dm_{}:matrix.org", i), RoomType::DirectMessage));
        }
        
        for i in 1..=3 {
            rooms.push((format!("!small_{}:matrix.org", i), RoomType::SmallGroup));
        }
        
        for i in 1..=2 {
            rooms.push((format!("!medium_{}:matrix.org", i), RoomType::MediumGroup));
        }
        
        rooms.push(("!large:matrix.org".to_string(), RoomType::LargeChannel));
        
        Self {
            user_id: user_id.to_string(),
            rooms,
        }
    }
    
    pub fn total_rooms(&self) -> usize {
        self.rooms.len()
    }
    
    pub fn total_olm_sessions(&self) -> usize {
        self.rooms.iter()
            .map(|(_, room_type)| room_type.member_count() - 1)
            .sum()
    }
}

/// Métricas de desempenho REAIS por sala
/// 
/// ESTRUTURA PAREADA (Caminho B):
/// - batch_id: Timestamp da execução completa (identifica conjunto de pares)
/// - pair_id: Identificador do par Classical↔Hybrid (ex: "pair_0", "pair_1")
/// - repeat_id: 0 = Classical, 1 = Hybrid (alternância de ordem por pair_id)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomBenchmark {
    // Identificadores
    pub batch_id: String,                  // Timestamp de execução (formato: YYYYMMDD_HHMMSS)
    pub pair_id: String,                   // Identificador do par (ex: "pair_0")
    pub repeat_id: u32,                    // 0 = Classical, 1 = Hybrid
    pub room_id: String,
    pub room_type: String,
    pub member_count: usize,
    pub crypto_mode: String,               // "Classical" ou "Hybrid"
    
    // Métricas de tempo (agregadas - compatibilidade)
    pub room_creation_ms: f64,
    pub add_members_ms: f64,
    pub session_setup_ms: f64,
    pub message_encrypt_ms: f64,           // Com gerenciamento de sala
    pub message_encrypt_pure_ms: f64,      // Apenas Megolm puro
    pub message_decrypt_ms: f64,
    pub total_setup_ms: f64,
    
    // PHASE-SEPARATED TIME METRICS
    pub setup_time_ms: f64,                // APENAS handshake inicial (session_setup)
    pub rotation_time_ms: f64,             // APENAS custo de rotações Megolm
    pub encrypt_steady_state_ms: f64,      // Criptografia sem rotações
    
    // Hardware profile 
    pub device_type: String,               // "Mobile", "Desktop", "IoT", "Server"
    pub architecture: String,              // "x86_64", "ARM", etc.
    pub cpu_cores: usize,
    pub cpu_freq_mhz: u32,
    
    // Rotation policy 
    pub rotation_policy: String,           // "Paranoid", "Balanced", "Relaxed"
    pub actual_rotations: usize,           // Rotações que ocorreram
    
    // Double Ratchet advances 
    pub num_ratchet_advances: usize,       // Total de avanços (simétricos + assimétricos)
    pub num_asymmetric_advances: usize,    // Apenas mudanças de direção
    pub num_rotation_messages: usize,      // Mensagens enviadas durante rotação (contador real)
    
    // Bandwidth
    pub kem_handshake_bytes: usize,
    pub olm_session_bytes: usize,
    pub megolm_session_bytes: usize,
    pub message_overhead_bytes: usize,
    pub total_bandwidth_bytes: usize,
    
    // ============= NOVAS MÉTRICAS REFINADAS =============
    // COMPARAÇÃO 1: Overhead PQC (Clássico vs Híbrido)
    pub bandwidth_agreement: usize,                     // 1.1) PQXDH/3DH handshake
    pub bandwidth_agreement_classical: usize,           // Parte clássica
    pub bandwidth_agreement_pqc: usize,                 // Parte PQC
    
    pub bandwidth_initial_distribution: usize,          // 1.2) Distribuição inicial Megolm
    pub bandwidth_initial_distribution_classical: usize, // Parte clássica
    pub bandwidth_initial_distribution_pqc: usize,       // Parte PQC
    
    pub bandwidth_rotation: usize,                      // 1.3) Redistribuição por rotação
    pub bandwidth_rotation_classical: usize,            // Parte clássica
    pub bandwidth_rotation_pqc: usize,                  // Parte PQC
    
    pub bandwidth_megolm_messages: usize,               // 1.4) Mensagens Megolm (NÃO PQC)
    
    // COMPARAÇÃO 2: Controle vs Dados
    pub bandwidth_control_plane: usize,                 // Acordo + Distribuição + Rotação
    pub bandwidth_data_plane: usize,                    // Mensagens Megolm cifradas
    
    // ============= PRIMITIVAS ISOLADAS =============
    // Agreement primitives
    pub bandwidth_agreement_primitives_identity_keys: usize,
    pub bandwidth_agreement_primitives_otk: usize,
    pub bandwidth_agreement_primitives_kyber1024: usize,
    pub bandwidth_agreement_primitives_prekey_overhead: usize,
    
    // Initial Distribution primitives
    pub bandwidth_initial_distribution_primitives_megolm_key: usize,
    pub bandwidth_initial_distribution_primitives_ratchet_key: usize,
    pub bandwidth_initial_distribution_primitives_kem_ct: usize,
    pub bandwidth_initial_distribution_primitives_olm_overhead: usize,
    
    // Rotation primitives
    pub bandwidth_rotation_primitives_megolm_key: usize,
    pub bandwidth_rotation_primitives_ratchet_key: usize,
    pub bandwidth_rotation_primitives_kem_ct: usize,
    pub bandwidth_rotation_primitives_olm_overhead: usize,
}

/// Métricas agregadas do perfil completo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileBenchmark {
    pub crypto_mode: String,
    pub hostname: String,
    pub cpu_info: String,
    pub num_cpus: usize,
    pub total_rooms: usize,
    pub total_olm_sessions: usize,
    pub rooms: Vec<RoomBenchmark>,
    pub total_setup_ms: f64,
    pub avg_message_encrypt_ms: f64,
    pub avg_message_decrypt_ms: f64,
}

fn get_system_info() -> (String, String, usize) {
    let hostname = hostname::get()
        .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
        .to_string_lossy()
        .to_string();
    
    let cpu_info = sys_info::cpu_speed()
        .map(|mhz| format!("{} MHz", mhz))
        .unwrap_or_else(|_| "unknown".to_string());
    
    let num_cpus = num_cpus::get();
    
    (hostname, cpu_info, num_cpus)
}

/// Benchmarca UMA sala individual (útil para quick test)
pub fn benchmark_room(
    batch_id: &str,
    pair_id: &str,
    repeat_id: u32,
    room_id: &str,
    room_type: RoomType,
    crypto_mode: &CryptoMode,
    rotation_policy: RotationPolicy,
    num_senders: Option<usize>,
) -> Result<RoomBenchmark> {
    let member_count = room_type.member_count();
    let mode_name = match crypto_mode {
        CryptoMode::Classical => "Classical",
        CryptoMode::Hybrid => "Hybrid",
    };
    
    let start = Instant::now();
    let mut room = MatrixRoom::new(
        room_id.to_string(),
        crypto_mode.clone(),
        rotation_policy,
    );
    let room_creation_ms = start.elapsed().as_secs_f64() * 1000.0;
    
    let start = Instant::now();
    let members: Vec<String> = (0..member_count)
        .map(|i| format!("@user{}:matrix.org", i))
        .collect();
    
    for member in &members {
        room.add_member(member.clone())?;
    }
    let add_members_ms = start.elapsed().as_secs_f64() * 1000.0;
    
    // ============================================================================
    // SENDER SETUP: Configurável via parâmetro
    // ============================================================================
    // - num_senders = None (default): 1 sender (single-user profile)
    // - num_senders = Some(1): 1 sender explícito
    // - num_senders = Some(3): 3 senders (multi-sender para quick-test/debug)
    // - num_senders = Some(n): n senders
    //
    // SINGLE-USER (1 sender): Mede experiência do usuário
    // - O usuário envia mensagens nas suas salas
    // - Simula: Um dispositivo mobile/desktop do usuário
    //
    // MULTI-SENDER (3+ senders): Melhor para testar forced_ratchet
    // - Múltiplos usuários enviam mensagens
    // - Cria tráfego bidirecional natural
    // - Útil para debug e validação
    
    let num_active_senders = num_senders.unwrap_or(1); // Default: 1 sender (user-profile)
    let num_active_senders = std::cmp::min(num_active_senders, member_count); // Não exceder membros
    let active_senders: Vec<String> = members.iter()
        .take(num_active_senders)
        .cloned()
        .collect();
    
    if num_active_senders == 1 {
        vlog!(VerbosityLevel::Verbose, "   - [SINGLE-USER] Configurando 1 sender ativo (experiência do usuário): {:?}", active_senders);
    } else {
        vlog!(VerbosityLevel::Verbose, "   - [MULTI-SENDER] Configurando {} senders ativos: {:?}", num_active_senders, active_senders);
    }
    
    // Para medição de decrypt, usar receiver diferente dos senders
    let receiver_id = &members[num_active_senders % member_count];
    
    let start = Instant::now();
    // ============================================================================
    // SETUP: Criar sessões Megolm para TODOS os senders ativos
    // ============================================================================
    vlog!(VerbosityLevel::Verbose, "   - Criando sessões Megolm para {} senders ativos", num_active_senders);
    room.create_sessions_for_senders(&active_senders)?;
    let session_setup_ms = start.elapsed().as_secs_f64() * 1000.0;
    
    // ============================================================================
    // WARM-UP BIDIRECIONAL: Estabelecer peer_key em todas as sessões Olm
    // ============================================================================
    // CRÍTICO para forced_ratchet funcionar nas rotações:
    // - Sessões Olm recém-criadas são "lazy" (sem peer_key)
    // - forced_ratchet_advance() precisa de peer_key para executar KEM
    // - Warm-up envia mensagens dummy em TODAS as direções (A→B e B→A)
    // - Após warm-up, todas as sessões inbound têm peer_key estabelecido
    // - Resultado: forced_ratchet pode executar KEM em TODAS as rotações
    // 
    // JUSTIFICATIVA: Mesmo com apenas 1 sender ativo (single-user profile),
    // o warm-up simula interações bidirecionais naturais do Matrix real:
    // - Outros usuários respondem mensagens
    // - Device verification (E2EE)
    // - Read receipts, typing notifications, etc.
    vlog!(VerbosityLevel::Verbose, "   - Executando warm-up bidirecional para estabelecer peer_key");
    room.warmup_olm_sessions_bidirectional()?;
    
    // SEED FIXA para reprodutibilidade: garante mensagens idênticas entre Classical e Hybrid
    // Seed derivada de: batch_id + room_type + rotation_policy + pair_id
    // Isso garante que o mesmo par (Classical↔Hybrid) recebe EXATAMENTE as mesmas mensagens
    let seed = format!("{}{:?}{:?}{}", batch_id, room_type, rotation_policy, pair_id)
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
    
    let scenario = room_type.to_usage_scenario();
    let mut msg_gen = MessageGenerator::new_with_seed(scenario, seed);
    
    // Warmup: primeira mensagem (pode ser mais lenta)
    let plaintext_warmup = b"Warmup message";
    let _ = room.send_message(&active_senders[0], plaintext_warmup)?;
    
    // ============================================================================
    // Benchmark 1: Encrypt via send_message (SINGLE-USER)
    // ============================================================================
    // Mensagens são enviadas pelo usuário sendo medido (single sender)
    // Simula: Um usuário enviando mensagens nas suas salas durante o dia
    // 
    // Com num_active_senders = 1, todas as mensagens vêm do mesmo sender (user0)
    // 
    // Rotações Megolm: Ocorrem automaticamente a cada N mensagens
    // - O usuário cria nova sessão Megolm
    // - Distribui nova chave via Olm para todos os membros da sala
    // - forced_ratchet executa KEM nas sessões Olm (graças ao warm-up)
    
    let iterations = room_type.messages_to_send();
    let mut encrypted_messages = Vec::new();
    let start = Instant::now();
    for i in 0..iterations {
        let msg = msg_gen.generate_message();
        let plaintext = msg_gen.message_to_bytes(&msg);
        
        // Com 1 sender ativo, sempre usa active_senders[0]
        let sender_idx = i % num_active_senders;
        let sender_id = &active_senders[sender_idx];
        
        let encrypted = room.send_message(sender_id, &plaintext)?;
        encrypted_messages.push(encrypted);
    }
    let encrypt_total_with_management = start.elapsed().as_secs_f64() * 1000.0;
    let message_encrypt_ms = encrypt_total_with_management / iterations as f64;
    
    // ============================================================================
    // Benchmark 2: Encrypt puro (apenas Megolm, sem gerenciamento)
    // ============================================================================
    // Usar o sender ativo (usuário sendo medido) para medição de encrypt puro
    let primary_sender_id = &active_senders[0];
    let sender_member = room.members.get_mut(primary_sender_id)
        .ok_or_else(|| anyhow::anyhow!("Sender não encontrado"))?;
    let sender_session = room.sender_sessions.get_mut(primary_sender_id)
        .ok_or_else(|| anyhow::anyhow!("Sessão outbound não encontrada"))?;
    
    // Criar nova instância do MessageGenerator para Benchmark 2 (não reutilizar do Benchmark 1)
    let mut msg_gen_pure = MessageGenerator::new_with_seed(scenario, seed);
    
    let start = Instant::now();
    for _i in 0..iterations {
        let msg = msg_gen_pure.generate_message();
        let plaintext = msg_gen.message_to_bytes(&msg);
        let _ = sender_member.crypto.megolm_encrypt(sender_session, &plaintext);
    }
    let encrypt_total_pure = start.elapsed().as_secs_f64() * 1000.0;
    let message_encrypt_pure_ms = encrypt_total_pure / iterations as f64;
    
    // Benchmark decrypt: decifrar as 100 mensagens já criptografadas
    // (Reutiliza encrypted_messages do benchmark 1, evitando dobrar rotações)
    let start = Instant::now();
    for encrypted in &encrypted_messages {
        let _ = room.decrypt_message(receiver_id, encrypted);
    }
    let decrypt_total = start.elapsed().as_secs_f64() * 1000.0;
    let message_decrypt_ms = decrypt_total / iterations as f64;
    
    let total_setup_ms = room_creation_ms + add_members_ms + session_setup_ms;
    
    // PHASE-SEPARATED TIME METRICS (alinhamento com Cenário 1)
    // FASE 1: Setup = Agreement + Initial Distribution
    let setup_time_ms = session_setup_ms;
    
    // FASE 2: Rotation = Tempo REAL medido durante rotate_megolm_only()
    // IMPORTANTE: Usar métrica REAL do room (alinhada com bandwidth_rotation)
    let rotation_time_ms = room.time_rotation_ms;
    
    // FASE 3: Encrypt steady-state = criptografia pura sem overhead
    // Usar message_encrypt_pure_ms que é apenas Megolm AES-256
    let encrypt_steady_state_ms = message_encrypt_pure_ms;
    
    // Detectar perfil de hardware
    let hardware = HardwareProfile::detect();
    
    // Obter política de rotação da sala e contador de rotações real
    let rotation_policy = room.rotation_policy.clone();
    let rotation_metrics = RotationMetrics::new(&rotation_policy, room.rotation_count);
    
    // Calcular métricas de largura de banda
    let bandwidth = calculate_bandwidth(&room, member_count, iterations, &crypto_mode);
    
    Ok(RoomBenchmark {
        batch_id: batch_id.to_string(),
        pair_id: pair_id.to_string(),
        repeat_id,
        room_id: room_id.to_string(),
        room_type: room_type.name().to_string(),
        member_count,
        crypto_mode: mode_name.to_string(),
        room_creation_ms,
        add_members_ms,
        session_setup_ms,
        message_encrypt_ms,
        message_encrypt_pure_ms,
        message_decrypt_ms,
        total_setup_ms,
        
        // PHASE-SEPARATED TIME METRICS
        setup_time_ms,
        rotation_time_ms,
        encrypt_steady_state_ms,
        
        // Hardware profile
        device_type: hardware.device_type,
        architecture: hardware.architecture,
        cpu_cores: hardware.cpu_cores,
        cpu_freq_mhz: hardware.cpu_freq_mhz,
        
        // Rotation metrics
        rotation_policy: rotation_metrics.policy_type,
        actual_rotations: rotation_metrics.actual_rotations,
        
        // Double Ratchet advances
        num_ratchet_advances: room.num_ratchet_advances,
        num_asymmetric_advances: room.num_asymmetric_advances,
        num_rotation_messages: room.num_rotation_messages,
        
        // Bandwidth metrics
        kem_handshake_bytes: bandwidth.kem_handshake_bytes,
        olm_session_bytes: bandwidth.olm_session_bytes,
        megolm_session_bytes: bandwidth.megolm_session_bytes,
        message_overhead_bytes: bandwidth.message_overhead_bytes,
        total_bandwidth_bytes: bandwidth.total_tx_bytes + bandwidth.total_rx_bytes,
        
        // ============= NOVAS MÉTRICAS REFINADAS =============
        // COMPARAÇÃO 1: Overhead PQC
        bandwidth_agreement: room.bandwidth_agreement,
        bandwidth_agreement_classical: room.bandwidth_agreement_classical,
        bandwidth_agreement_pqc: room.bandwidth_agreement_pqc,
        
        bandwidth_initial_distribution: room.bandwidth_initial_distribution,
        bandwidth_initial_distribution_classical: room.bandwidth_initial_distribution_classical,
        bandwidth_initial_distribution_pqc: room.bandwidth_initial_distribution_pqc,
        
        bandwidth_rotation: room.bandwidth_rotation,
        bandwidth_rotation_classical: room.bandwidth_rotation_classical,
        bandwidth_rotation_pqc: room.bandwidth_rotation_pqc,
        
        bandwidth_megolm_messages: room.bandwidth_megolm_messages,
        
        // COMPARAÇÃO 2: Controle vs Dados
        bandwidth_control_plane: room.bandwidth_control_plane,
        bandwidth_data_plane: room.bandwidth_data_plane,
        
        // ============= PRIMITIVAS ISOLADAS =============
        bandwidth_agreement_primitives_identity_keys: room.bandwidth_agreement_primitives_identity_keys,
        bandwidth_agreement_primitives_otk: room.bandwidth_agreement_primitives_otk,
        bandwidth_agreement_primitives_kyber1024: room.bandwidth_agreement_primitives_kyber1024,
        bandwidth_agreement_primitives_prekey_overhead: room.bandwidth_agreement_primitives_prekey_overhead,
        
        bandwidth_initial_distribution_primitives_megolm_key: room.bandwidth_initial_distribution_primitives_megolm_key,
        bandwidth_initial_distribution_primitives_ratchet_key: room.bandwidth_initial_distribution_primitives_ratchet_key,
        bandwidth_initial_distribution_primitives_kem_ct: room.bandwidth_initial_distribution_primitives_kem_ct,
        bandwidth_initial_distribution_primitives_olm_overhead: room.bandwidth_initial_distribution_primitives_olm_overhead,
        
        bandwidth_rotation_primitives_megolm_key: room.bandwidth_rotation_primitives_megolm_key,
        bandwidth_rotation_primitives_ratchet_key: room.bandwidth_rotation_primitives_ratchet_key,
        bandwidth_rotation_primitives_kem_ct: room.bandwidth_rotation_primitives_kem_ct,
        bandwidth_rotation_primitives_olm_overhead: room.bandwidth_rotation_primitives_olm_overhead,
    })
}

/// Calcula métricas de largura de banda para uma sala (usando valores reais medidos)
fn calculate_bandwidth(
    room: &MatrixRoom,
    _member_count: usize,
    _num_messages: usize,
    _crypto_mode: &CryptoMode,
) -> BandwidthMetrics {
    // Usar valores REAIS medidos pela sala ao invés de estimativas
    let kem_handshake_bytes = room.bandwidth_key_exchange; // PQXDH key exchange real
    let olm_session_bytes = room.bandwidth_session_distribution; // Megolm key distribution via Olm
    let megolm_session_bytes: usize = room.bandwidth_rekeying; // Double Ratchet PQC (direction changes)
    let message_overhead_bytes = room.bandwidth_messages; // Megolm encrypted messages
    
    // Custo de rotação = redistribuição de chaves após rotação
    // (já incluído em bandwidth_session_distribution durante rotações)
    let rotation_cost_bytes = if room.rotation_count > 0 {
        room.bandwidth_session_distribution / (room.rotation_count + 1)
    } else {
        0
    };
    
    let total_tx_bytes = kem_handshake_bytes + olm_session_bytes + megolm_session_bytes + message_overhead_bytes;
    
    BandwidthMetrics {
        kem_handshake_bytes,
        olm_session_bytes,
        megolm_session_bytes,
        message_overhead_bytes,
        rotation_cost_bytes,
        total_tx_bytes,
        total_rx_bytes: total_tx_bytes, // Simplificação: TX == RX
    }
}

fn benchmark_profile(
    batch_id: &str,
    pair_id: &str,
    repeat_id: u32,
    profile: &UserProfile,
    crypto_mode: CryptoMode,
    rotation_policy: RotationPolicy,
) -> Result<ProfileBenchmark> {
    let (hostname, cpu_info, num_cpus) = get_system_info();
    let mode_name = match crypto_mode {
        CryptoMode::Classical => "Classical",
        CryptoMode::Hybrid => "Hybrid",
    };
    
    vlog!(VerbosityLevel::Minimal, "  Benchmarking {} com {} salas...", mode_name, profile.total_rooms());
    
    let mut room_benchmarks = Vec::new();
    let mut total_setup_ms = 0.0;
    let mut total_encrypt_ms = 0.0;
    let mut total_decrypt_ms = 0.0;
    
    for (i, (room_id, room_type)) in profile.rooms.iter().enumerate() {
        vlog!(VerbosityLevel::Normal, "    Sala {}/{}: {} ({} membros)", 
                 i + 1, profile.total_rooms(), 
                 room_type.name(), room_type.member_count());
        
        let bench = benchmark_room(batch_id, pair_id, repeat_id, room_id, *room_type, &crypto_mode, rotation_policy, None)?;
        
        total_setup_ms += bench.total_setup_ms;
        total_encrypt_ms += bench.message_encrypt_ms;
        total_decrypt_ms += bench.message_decrypt_ms;
        
        room_benchmarks.push(bench);
    }
    
    let avg_encrypt = total_encrypt_ms / profile.total_rooms() as f64;
    let avg_decrypt = total_decrypt_ms / profile.total_rooms() as f64;
    
    Ok(ProfileBenchmark {
        crypto_mode: mode_name.to_string(),
        hostname,
        cpu_info,
        num_cpus,
        total_rooms: profile.total_rooms(),
        total_olm_sessions: profile.total_olm_sessions(),
        rooms: room_benchmarks,
        total_setup_ms,
        avg_message_encrypt_ms: avg_encrypt,
        avg_message_decrypt_ms: avg_decrypt,
    })
}

/// Resultados pareados por repetição (formato long/tidy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedRun {
    pub batch_id: String,
    pub pair_id: String,
    pub repeat_id: u32,
    pub user_profile: String,
    pub rooms: Vec<RoomBenchmark>,
}

/// Resultados agregados (compatibilidade com código antigo)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparativeResults {
    pub user_profile: String,
    pub timestamp: String,
    pub classical: ProfileBenchmark,
    pub hybrid: ProfileBenchmark,
    pub setup_overhead_pct: f64,
    pub encrypt_overhead_pct: f64,
}

/// Executa benchmark pareado com N repetições
/// 
/// DESIGN PAREADO (Caminho B):
/// - Para cada pair_id (0..repetitions):
///   * Se pair_id é PAR:   Classical → Hybrid
///   * Se pair_id é ÍMPAR: Hybrid → Classical
/// - Alternância controla efeitos de cache/aquecimento
pub fn run_paired_benchmark(user_id: &str, repetitions: usize, rotation_policy: Option<RotationPolicy>) -> Result<Vec<PairedRun>> {
    println!("\n=== Benchmark Pareado de Perfil de Usuário ===\n");
    
    let profile = UserProfile::typical(user_id);
    let batch_id = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let policy = rotation_policy.unwrap_or(RotationPolicy::Balanced);
    
    println!("Perfil: {}", profile.user_id);
    println!("  Salas: {}", profile.total_rooms());
    println!("  Sessões Olm: {}", profile.total_olm_sessions());
    println!("  Repetições: {} pares Classical↔Hybrid", repetitions);
    println!("  Política de rotação: {:?}\n", policy);
    
    let mut all_runs = Vec::new();
    
    for pair_idx in 0..repetitions {
        let pair_id = format!("pair_{}", pair_idx);
        
        // Alternância de ordem: par = Classical→Hybrid, ímpar = Hybrid→Classical
        let (first_mode, first_repeat, second_mode, second_repeat) = if pair_idx % 2 == 0 {
            (CryptoMode::Classical, 0, CryptoMode::Hybrid, 1)
        } else {
            (CryptoMode::Hybrid, 1, CryptoMode::Classical, 0)
        };
        
        let first_mode_name = if first_repeat == 0 { "Classical" } else { "Hybrid" };
        let second_mode_name = if second_repeat == 0 { "Classical" } else { "Hybrid" };
        
        progress!("Par {}/{} (ordem: {} → {})", 
                 pair_idx + 1, repetitions, first_mode_name, second_mode_name);
        
        // Primeira execução do par
        let first_bench = benchmark_profile(&batch_id, &pair_id, first_repeat, &profile, first_mode, policy)?;
        all_runs.push(PairedRun {
            batch_id: batch_id.clone(),
            pair_id: pair_id.clone(),
            repeat_id: first_repeat,
            user_profile: profile.user_id.clone(),
            rooms: first_bench.rooms,
        });
        
        // Segunda execução do par
        let second_bench = benchmark_profile(&batch_id, &pair_id, second_repeat, &profile, second_mode, policy)?;
        all_runs.push(PairedRun {
            batch_id: batch_id.clone(),
            pair_id: pair_id.clone(),
            repeat_id: second_repeat,
            user_profile: profile.user_id.clone(),
            rooms: second_bench.rooms,
        });
        
        println!();
    }
    
    Ok(all_runs)
}

/// Salva runs pareados em formato long/tidy (para analyze.py)
pub fn save_paired_runs_csv(runs: &[PairedRun], filename: &str) -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    let mut file = File::create(filename)?;
    
    // Cabeçalho CSV estendido com hardware, rotação, bandwidth e PRIMITIVAS
    writeln!(file, "batch_id,pair_id,repeat_id,user_profile,room_id,room_type,member_count,crypto_mode,\
room_creation_ms,add_members_ms,session_setup_ms,message_encrypt_ms,message_encrypt_pure_ms,message_decrypt_ms,total_setup_ms,\
setup_time_ms,rotation_time_ms,encrypt_steady_state_ms,\
device_type,architecture,cpu_cores,cpu_freq_mhz,\
rotation_policy,actual_rotations,\
kem_handshake_bytes,olm_session_bytes,megolm_session_bytes,message_overhead_bytes,total_bandwidth_bytes,\
num_ratchet_advances,num_asymmetric_advances,num_rotation_messages,\
bandwidth_agreement,bandwidth_agreement_classical,bandwidth_agreement_pqc,\
bandwidth_initial_distribution,bandwidth_initial_distribution_classical,bandwidth_initial_distribution_pqc,\
bandwidth_rotation,bandwidth_rotation_classical,bandwidth_rotation_pqc,\
bandwidth_megolm_messages,bandwidth_control_plane,bandwidth_data_plane,\
bandwidth_agreement_primitives_identity_keys,bandwidth_agreement_primitives_otk,bandwidth_agreement_primitives_kyber1024,bandwidth_agreement_primitives_prekey_overhead,\
bandwidth_initial_distribution_primitives_megolm_key,bandwidth_initial_distribution_primitives_ratchet_key,bandwidth_initial_distribution_primitives_kem_ct,bandwidth_initial_distribution_primitives_olm_overhead,\
bandwidth_rotation_primitives_megolm_key,bandwidth_rotation_primitives_ratchet_key,bandwidth_rotation_primitives_kem_ct,bandwidth_rotation_primitives_olm_overhead")?;
    
    // Cada run com suas salas
    for run in runs {
        for room in &run.rooms {
            writeln!(file, "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                room.batch_id,
                room.pair_id,
                room.repeat_id,
                run.user_profile,
                room.room_id,
                room.room_type,
                room.member_count,
                room.crypto_mode,
                room.room_creation_ms,
                room.add_members_ms,
                room.session_setup_ms,
                room.message_encrypt_ms,
                room.message_encrypt_pure_ms,
                room.message_decrypt_ms,
                room.total_setup_ms,
                room.setup_time_ms,
                room.rotation_time_ms,
                room.encrypt_steady_state_ms,
                room.device_type,
                room.architecture,
                room.cpu_cores,
                room.cpu_freq_mhz,
                room.rotation_policy,
                room.actual_rotations,
                room.kem_handshake_bytes,
                room.olm_session_bytes,
                room.megolm_session_bytes,
                room.message_overhead_bytes,
                room.total_bandwidth_bytes,
                room.num_ratchet_advances,
                room.num_asymmetric_advances,
                room.num_rotation_messages,
                room.bandwidth_agreement,
                room.bandwidth_agreement_classical,
                room.bandwidth_agreement_pqc,
                room.bandwidth_initial_distribution,
                room.bandwidth_initial_distribution_classical,
                room.bandwidth_initial_distribution_pqc,
                room.bandwidth_rotation,
                room.bandwidth_rotation_classical,
                room.bandwidth_rotation_pqc,
                room.bandwidth_megolm_messages,
                room.bandwidth_control_plane,
                room.bandwidth_data_plane,
                room.bandwidth_agreement_primitives_identity_keys,
                room.bandwidth_agreement_primitives_otk,
                room.bandwidth_agreement_primitives_kyber1024,
                room.bandwidth_agreement_primitives_prekey_overhead,
                room.bandwidth_initial_distribution_primitives_megolm_key,
                room.bandwidth_initial_distribution_primitives_ratchet_key,
                room.bandwidth_initial_distribution_primitives_kem_ct,
                room.bandwidth_initial_distribution_primitives_olm_overhead,
                room.bandwidth_rotation_primitives_megolm_key,
                room.bandwidth_rotation_primitives_ratchet_key,
                room.bandwidth_rotation_primitives_kem_ct,
                room.bandwidth_rotation_primitives_olm_overhead)?;
        }
    }
    
    progress!(" Dados pareados (long/tidy) salvos: {}", filename);
    progress!("  (Formato: cada linha = uma sala em uma repetição)");
    progress!("  (Inclui hardware, rotação Megolm e largura de banda)");
    progress!("  (Análise: python scripts/analyze.py {})", filename);
    Ok(())
}

/// Função de compatibilidade (mantém API antiga)
pub fn run_comparative_benchmark(user_id: &str) -> Result<ComparativeResults> {
    println!("\n=== Benchmark de Perfil de Usuário - Modo Legado ===\n");
    println!("NOTA: Esta função usa apenas 1 repetição.");
    println!("      Para análise pareada robusta, use run_paired_benchmark()\n");
    
    let profile = UserProfile::typical(user_id);
    let batch_id = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    
    println!("Perfil: {}", profile.user_id);
    println!("  Salas: {}", profile.total_rooms());
    println!("  Sessões Olm: {}\n", profile.total_olm_sessions());
    
    println!("Benchmarking Classical...");
    let classical = benchmark_profile(&batch_id, "pair_0", 0, &profile, CryptoMode::Classical, RotationPolicy::Balanced)?;
    
    println!("\nBenchmarking Hybrid...");
    let hybrid = benchmark_profile(&batch_id, "pair_0", 1, &profile, CryptoMode::Hybrid, RotationPolicy::Balanced)?;
    
    let setup_overhead = ((hybrid.total_setup_ms - classical.total_setup_ms) 
        / classical.total_setup_ms) * 100.0;
    
    let encrypt_overhead = ((hybrid.avg_message_encrypt_ms - classical.avg_message_encrypt_ms) 
        / classical.avg_message_encrypt_ms) * 100.0;
    
    Ok(ComparativeResults {
        user_profile: profile.user_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        classical,
        hybrid,
        setup_overhead_pct: setup_overhead,
        encrypt_overhead_pct: encrypt_overhead,
    })
}

pub fn display_results(results: &ComparativeResults) {
    println!("\n=== Resultados - Hardware Real ===\n");
    
    println!("Sistema:");
    println!("  Hostname: {}", results.classical.hostname);
    println!("  CPU: {}", results.classical.cpu_info);
    println!("  Cores: {}\n", results.classical.num_cpus);
    
    println!("Perfil: {}", results.user_profile);
    println!("  Salas: {}", results.classical.total_rooms);
    println!("  Sessoes OLM: {}\n", results.classical.total_olm_sessions);
    
    println!("--- Setup Total (ms) ---");
    println!("Classical: {:.2}ms", results.classical.total_setup_ms);
    println!("Hybrid:    {:.2}ms (+{:.1}%)", 
             results.hybrid.total_setup_ms, results.setup_overhead_pct);
    println!();
    
    println!("--- Mensagens (ms/msg) ---");
    println!("Encrypt (com gerenciamento de sala):");
    println!("  Classical: {:.4}ms", results.classical.avg_message_encrypt_ms);
    println!("  Hybrid:    {:.4}ms (+{:.1}%)", 
             results.hybrid.avg_message_encrypt_ms, results.encrypt_overhead_pct);
    println!();
    
    // Calcular médias de encrypt puro
    let classical_pure_avg: f64 = results.classical.rooms.iter()
        .map(|r| r.message_encrypt_pure_ms)
        .sum::<f64>() / results.classical.rooms.len() as f64;
    let hybrid_pure_avg: f64 = results.hybrid.rooms.iter()
        .map(|r| r.message_encrypt_pure_ms)
        .sum::<f64>() / results.hybrid.rooms.len() as f64;
    let pure_overhead = ((hybrid_pure_avg - classical_pure_avg) / classical_pure_avg) * 100.0;
    
    println!("Encrypt PURO (apenas Megolm, sem gerenciamento):");
    println!("  Classical: {:.4}ms", classical_pure_avg);
    println!("  Hybrid:    {:.4}ms ({:+.1}%)", hybrid_pure_avg, pure_overhead);
    println!();
    
    println!("Decrypt:");
    println!("  Classical: {:.4}ms", results.classical.avg_message_decrypt_ms);
    println!("  Hybrid:    {:.4}ms", results.hybrid.avg_message_decrypt_ms);
    println!();
    
    println!("--- Breakdown por Tipo de Sala ---");
    println!("+---------------+-----------+-----------+----------+");
    println!("| Tipo          | Classical | Hybrid    | Overhead |");
    println!("+---------------+-----------+-----------+----------+");
    
    for i in 0..results.classical.rooms.len() {
        let c = &results.classical.rooms[i];
        let h = &results.hybrid.rooms[i];
        let overhead = ((h.total_setup_ms - c.total_setup_ms) / c.total_setup_ms) * 100.0;
        
        println!("| {:<13} | {:>7.2}ms | {:>7.2}ms | {:>6.1}% |",
                 c.room_type, c.total_setup_ms, h.total_setup_ms, overhead);
    }
    println!("+---------------+-----------+-----------+----------+");
}

pub fn save_results_json(results: &ComparativeResults, filename: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(filename, json)?;
    println!("Salvo: {}", filename);
    Ok(())
}

pub fn save_results_csv(results: &ComparativeResults, filename: &str) -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    let mut file = File::create(filename)?;
    
    writeln!(file, "batch_id,pair_id,repeat_id,crypto_mode,room_type,member_count,room_creation_ms,add_members_ms,session_setup_ms,message_encrypt_ms,message_encrypt_pure_ms,message_decrypt_ms,total_setup_ms")?;
    
    let write_rooms = |file: &mut File, profile: &ProfileBenchmark| -> Result<()> {
        for room in &profile.rooms {
            writeln!(file, "{},{},{},{},{},{},{},{},{},{},{},{},{}",
                room.batch_id,
                room.pair_id,
                room.repeat_id,
                room.crypto_mode,
                room.room_type,
                room.member_count,
                room.room_creation_ms,
                room.add_members_ms,
                room.session_setup_ms,
                room.message_encrypt_ms,
                room.message_encrypt_pure_ms,
                room.message_decrypt_ms,
                room.total_setup_ms)?;
        }
        Ok(())
    };
    
    write_rooms(&mut file, &results.classical)?;
    write_rooms(&mut file, &results.hybrid)?;
    
    println!("Salvo: {}", filename);
    Ok(())
}
