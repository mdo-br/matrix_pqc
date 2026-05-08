// Structs e enums de métricas do benchmark PQC

use serde::{Deserialize, Serialize};
use crate::protocols::room::RotationPolicy;

/// Perfil de hardware do dispositivo cliente
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub device_type: String,
    pub architecture: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_freq_mhz: u32,
    pub ram_mb: usize,
    pub platform_id: String,
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
        }
        .to_string();

        let ram_mb = sys_info::mem_info()
            .map(|info| (info.total / 1024) as usize)
            .unwrap_or(0);

        let cpu_freq_mhz = sys_info::cpu_speed().unwrap_or(0) as u32;

        // Classificação baseada em dados reais de hardware (RAM + núcleos):
        //   ≤1 GB               → IoT        (microcontroladores, RPi Zero)
        //   ≤8 GB  + ARM64      → EmbeddedSBC (Jetson Orin/Nano, RPi 4/5)
        //   ≤8 GB  + x86/outro  → Mobile     (laptops, netbooks)
        //   ≤64 GB              → Desktop    (workstations típicas)
        //   >64 GB              → Server     (rack, nuvem)
        let ram_gb = ram_mb / 1024;
        let is_arm64 = cfg!(target_arch = "aarch64");
        let device_type = if ram_gb <= 1 {
            "IoT"
        } else if ram_gb <= 8 && is_arm64 {
            "EmbeddedSBC"
        } else if ram_gb <= 8 {
            "Mobile"
        } else if ram_gb <= 64 {
            "Desktop"
        } else {
            "Server"
        }
        .to_string();

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
    pub policy_type: String,
    pub actual_rotations: usize,
    pub messages_between_rotations: Vec<usize>,
}

impl RotationMetrics {
    pub fn new(policy: &RotationPolicy, actual_rotations: usize) -> Self {
        let policy_type = match policy {
            RotationPolicy::Paranoid => "Paranoid",
            RotationPolicy::PQ3 => "PQ3",
            RotationPolicy::Balanced => "Balanced",
            RotationPolicy::Relaxed => "Relaxed",
        }
        .to_string();

        Self {
            policy_type,
            actual_rotations,
            messages_between_rotations: Vec::new(),
        }
    }
}

/// Métricas de largura de banda
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BandwidthMetrics {
    pub kem_handshake_bytes: usize,
    pub olm_session_bytes: usize,
    pub megolm_session_bytes: usize,
    pub message_overhead_bytes: usize,
    pub rotation_cost_bytes: usize,
    pub total_tx_bytes: usize,
    pub total_rx_bytes: usize,
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

    /// Número de mensagens a enviar por tipo de sala
    ///
    /// Calibrado para garantir múltiplas rotações em todas as políticas:
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
    pub fn to_usage_scenario(&self) -> super::workload::UsageScenario {
        match self {
            RoomType::DirectMessage => super::workload::UsageScenario::SmallChat,
            RoomType::SmallGroup => super::workload::UsageScenario::SmallChat,
            RoomType::MediumGroup => super::workload::UsageScenario::MediumGroup,
            RoomType::LargeChannel => super::workload::UsageScenario::LargeChannel,
        }
    }
}

/// Perfil de uso do usuário (conjunto de salas)
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

        Self { user_id: user_id.to_string(), rooms }
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

/// Métricas de desempenho por sala (formato pareado)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomBenchmark {
    pub batch_id: String,
    pub pair_id: String,
    pub repeat_id: u32,
    pub room_id: String,
    pub room_type: String,
    pub member_count: usize,
    pub crypto_mode: String,

    pub room_creation_ms: f64,
    pub add_members_ms: f64,
    pub session_setup_ms: f64,
    pub message_encrypt_ms: f64,
    pub message_encrypt_pure_ms: f64,
    pub message_decrypt_ms: f64,
    pub total_setup_ms: f64,

    pub setup_time_ms: f64,
    pub rotation_time_ms: f64,
    pub encrypt_steady_state_ms: f64,

    pub device_type: String,
    pub architecture: String,
    pub cpu_cores: usize,
    pub cpu_freq_mhz: u32,

    pub rotation_policy: String,
    pub actual_rotations: usize,

    pub num_ratchet_advances: usize,
    pub num_asymmetric_advances: usize,
    pub num_rotation_messages: usize,

    pub kem_handshake_bytes: usize,
    pub olm_session_bytes: usize,
    pub megolm_session_bytes: usize,
    pub message_overhead_bytes: usize,
    pub total_bandwidth_bytes: usize,

    // Overhead PQC por fase
    pub bandwidth_agreement: usize,
    pub bandwidth_agreement_classical: usize,
    pub bandwidth_agreement_pqc: usize,

    pub bandwidth_initial_distribution: usize,
    pub bandwidth_initial_distribution_classical: usize,
    pub bandwidth_initial_distribution_pqc: usize,

    pub bandwidth_rotation: usize,
    pub bandwidth_rotation_classical: usize,
    pub bandwidth_rotation_pqc: usize,

    pub bandwidth_megolm_messages: usize,

    pub bandwidth_control_plane: usize,
    pub bandwidth_data_plane: usize,

    // Primitivas isoladas — Agreement
    pub bandwidth_agreement_primitives_identity_keys: usize,
    pub bandwidth_agreement_primitives_otk: usize,
    pub bandwidth_agreement_primitives_kyber1024: usize,
    pub bandwidth_agreement_primitives_prekey_overhead: usize,

    // Primitivas isoladas — Initial Distribution
    pub bandwidth_initial_distribution_primitives_megolm_key: usize,
    pub bandwidth_initial_distribution_primitives_ratchet_key: usize,
    pub bandwidth_initial_distribution_primitives_kem_ct: usize,
    pub bandwidth_initial_distribution_primitives_olm_overhead: usize,

    // Primitivas isoladas — Rotation
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

/// Resultados pareados por repetição (formato long/tidy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedRun {
    pub batch_id: String,
    pub pair_id: String,
    pub repeat_id: u32,
    pub user_profile: String,
    pub rooms: Vec<RoomBenchmark>,
}
