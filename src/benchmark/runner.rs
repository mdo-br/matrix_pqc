// Orquestração do benchmark pareado Classical↔Hybrid

use anyhow::Result;
use serde::Serialize;
use std::time::Instant;
use crate::protocols::room::{MatrixRoom, CryptoMode, RotationPolicy};
use crate::utils::logging::VerbosityLevel;
use crate::{vlog, progress};
use super::metrics::{
    HardwareProfile, RotationMetrics, BandwidthMetrics,
    RoomType, UserProfile, RoomBenchmark, ProfileBenchmark, PairedRun,
};
use super::workload::MessageGenerator;

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

/// Benchmarca uma sala individual
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

    let num_active_senders = num_senders.unwrap_or(1);
    let num_active_senders = std::cmp::min(num_active_senders, member_count);
    let active_senders: Vec<String> = members.iter()
        .take(num_active_senders)
        .cloned()
        .collect();

    if num_active_senders == 1 {
        vlog!(VerbosityLevel::Verbose, "   - [SINGLE-USER] Configurando 1 sender ativo: {:?}", active_senders);
    } else {
        vlog!(VerbosityLevel::Verbose, "   - [MULTI-SENDER] Configurando {} senders ativos: {:?}", num_active_senders, active_senders);
    }

    let receiver_id = &members[num_active_senders % member_count];

    let start = Instant::now();
    room.create_sessions_for_senders(&active_senders)?;
    let session_setup_ms = start.elapsed().as_secs_f64() * 1000.0;

    vlog!(VerbosityLevel::Verbose, "   - Executando warm-up bidirecional para estabelecer peer_key");
    room.warmup_olm_sessions_bidirectional()?;

    // Seed derivada de batch_id + room_type + rotation_policy + pair_id para reprodutibilidade
    let seed = format!("{}{:?}{:?}{}", batch_id, room_type, rotation_policy, pair_id)
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));

    let scenario = room_type.to_usage_scenario();
    let mut msg_gen = MessageGenerator::new_with_seed(scenario, seed);

    // Warmup: primeira mensagem (pode ser mais lenta por lazy init)
    let _ = room.send_message(&active_senders[0], b"Warmup message")?;

    let iterations = room_type.messages_to_send();
    let mut encrypted_messages = Vec::new();
    let start = Instant::now();
    for i in 0..iterations {
        let msg = msg_gen.generate_message();
        let plaintext = msg_gen.message_to_bytes(&msg);
        let sender_idx = i % num_active_senders;
        let encrypted = room.send_message(&active_senders[sender_idx], &plaintext)?;
        encrypted_messages.push(encrypted);
    }
    let message_encrypt_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;

    // Encrypt puro (apenas Megolm, sem gerenciamento de sala)
    let primary_sender_id = &active_senders[0];
    let sender_member = room.members.get_mut(primary_sender_id)
        .ok_or_else(|| anyhow::anyhow!("Sender não encontrado"))?;
    let sender_session = room.sender_sessions.get_mut(primary_sender_id)
        .ok_or_else(|| anyhow::anyhow!("Sessão outbound não encontrada"))?;

    let mut msg_gen_pure = MessageGenerator::new_with_seed(scenario, seed);
    let start = Instant::now();
    for _ in 0..iterations {
        let msg = msg_gen_pure.generate_message();
        let plaintext = msg_gen_pure.message_to_bytes(&msg);
        let _ = sender_member.crypto.megolm_encrypt(sender_session, &plaintext);
    }
    let message_encrypt_pure_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;

    let start = Instant::now();
    for encrypted in &encrypted_messages {
        let _ = room.decrypt_message(receiver_id, encrypted);
    }
    let message_decrypt_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;

    let total_setup_ms = room_creation_ms + add_members_ms + session_setup_ms;
    let setup_time_ms = session_setup_ms;
    let rotation_time_ms = room.time_rotation_ms;
    let encrypt_steady_state_ms = message_encrypt_pure_ms;

    let hardware = HardwareProfile::detect();
    let rotation_policy_val = room.rotation_policy.clone();
    let rotation_metrics = RotationMetrics::new(&rotation_policy_val, room.rotation_count);
    let bandwidth = calculate_bandwidth(&room, member_count, iterations, crypto_mode);

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
        setup_time_ms,
        rotation_time_ms,
        encrypt_steady_state_ms,
        device_type: hardware.device_type,
        architecture: hardware.architecture,
        cpu_cores: hardware.cpu_cores,
        cpu_freq_mhz: hardware.cpu_freq_mhz,
        rotation_policy: rotation_metrics.policy_type,
        actual_rotations: rotation_metrics.actual_rotations,
        num_ratchet_advances: room.num_ratchet_advances,
        num_asymmetric_advances: room.num_asymmetric_advances,
        num_rotation_messages: room.num_rotation_messages,
        kem_handshake_bytes: bandwidth.kem_handshake_bytes,
        olm_session_bytes: bandwidth.olm_session_bytes,
        megolm_session_bytes: bandwidth.megolm_session_bytes,
        message_overhead_bytes: bandwidth.message_overhead_bytes,
        total_bandwidth_bytes: bandwidth.total_tx_bytes + bandwidth.total_rx_bytes,
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
        bandwidth_control_plane: room.bandwidth_control_plane,
        bandwidth_data_plane: room.bandwidth_data_plane,
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

fn calculate_bandwidth(
    room: &MatrixRoom,
    _member_count: usize,
    _num_messages: usize,
    _crypto_mode: &CryptoMode,
) -> BandwidthMetrics {
    let kem_handshake_bytes = room.bandwidth_key_exchange;
    let olm_session_bytes = room.bandwidth_session_distribution;
    let megolm_session_bytes = room.bandwidth_rekeying;
    let message_overhead_bytes = room.bandwidth_messages;

    let rotation_cost_bytes = if room.rotation_count > 0 {
        room.bandwidth_session_distribution / (room.rotation_count + 1)
    } else {
        0
    };

    let total_tx_bytes = kem_handshake_bytes + olm_session_bytes
        + megolm_session_bytes + message_overhead_bytes;

    BandwidthMetrics {
        kem_handshake_bytes,
        olm_session_bytes,
        megolm_session_bytes,
        message_overhead_bytes,
        rotation_cost_bytes,
        total_tx_bytes,
        total_rx_bytes: total_tx_bytes,
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

        let bench = benchmark_room(
            batch_id, pair_id, repeat_id,
            room_id, *room_type, &crypto_mode, rotation_policy, None,
        )?;

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

/// Executa benchmark pareado com N repetições (alternância Classical↔Hybrid)
///
/// Design pareado: para cada pair_id (0..repetitions):
/// - par: Classical → Hybrid
/// - ímpar: Hybrid → Classical
pub fn run_paired_benchmark(
    user_id: &str,
    repetitions: usize,
    rotation_policy: Option<RotationPolicy>,
) -> Result<Vec<PairedRun>> {
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

        let (first_mode, first_repeat, second_mode, second_repeat) = if pair_idx % 2 == 0 {
            (CryptoMode::Classical, 0, CryptoMode::Hybrid, 1)
        } else {
            (CryptoMode::Hybrid, 1, CryptoMode::Classical, 0)
        };

        let first_name = if first_repeat == 0 { "Classical" } else { "Hybrid" };
        let second_name = if second_repeat == 0 { "Classical" } else { "Hybrid" };

        progress!("Par {}/{} (ordem: {} → {})",
                 pair_idx + 1, repetitions, first_name, second_name);

        let first = benchmark_profile(&batch_id, &pair_id, first_repeat, &profile, first_mode, policy)?;
        all_runs.push(PairedRun {
            batch_id: batch_id.clone(),
            pair_id: pair_id.clone(),
            repeat_id: first_repeat,
            user_profile: profile.user_id.clone(),
            rooms: first.rooms,
        });

        let second = benchmark_profile(&batch_id, &pair_id, second_repeat, &profile, second_mode, policy)?;
        all_runs.push(PairedRun {
            batch_id: batch_id.clone(),
            pair_id: pair_id.clone(),
            repeat_id: second_repeat,
            user_profile: profile.user_id.clone(),
            rooms: second.rooms,
        });

        println!();
    }

    Ok(all_runs)
}

/// Salva runs pareados em CSV (formato long/tidy para analyze.py)
pub fn save_paired_runs_csv(runs: &[PairedRun], filename: &str) -> Result<()> {
    #[derive(Serialize)]
    struct CsvRow<'a> {
        batch_id: &'a str,
        pair_id: &'a str,
        repeat_id: u32,
        user_profile: &'a str,
        room_id: &'a str,
        room_type: &'a str,
        member_count: usize,
        crypto_mode: &'a str,
        room_creation_ms: f64,
        add_members_ms: f64,
        session_setup_ms: f64,
        message_encrypt_ms: f64,
        message_encrypt_pure_ms: f64,
        message_decrypt_ms: f64,
        total_setup_ms: f64,
        setup_time_ms: f64,
        rotation_time_ms: f64,
        encrypt_steady_state_ms: f64,
        device_type: &'a str,
        architecture: &'a str,
        cpu_cores: usize,
        cpu_freq_mhz: u32,
        rotation_policy: &'a str,
        actual_rotations: usize,
        kem_handshake_bytes: usize,
        olm_session_bytes: usize,
        megolm_session_bytes: usize,
        message_overhead_bytes: usize,
        total_bandwidth_bytes: usize,
        num_ratchet_advances: usize,
        num_asymmetric_advances: usize,
        num_rotation_messages: usize,
        bandwidth_agreement: usize,
        bandwidth_agreement_classical: usize,
        bandwidth_agreement_pqc: usize,
        bandwidth_initial_distribution: usize,
        bandwidth_initial_distribution_classical: usize,
        bandwidth_initial_distribution_pqc: usize,
        bandwidth_rotation: usize,
        bandwidth_rotation_classical: usize,
        bandwidth_rotation_pqc: usize,
        bandwidth_megolm_messages: usize,
        bandwidth_control_plane: usize,
        bandwidth_data_plane: usize,
        bandwidth_agreement_primitives_identity_keys: usize,
        bandwidth_agreement_primitives_otk: usize,
        bandwidth_agreement_primitives_kyber1024: usize,
        bandwidth_agreement_primitives_prekey_overhead: usize,
        bandwidth_initial_distribution_primitives_megolm_key: usize,
        bandwidth_initial_distribution_primitives_ratchet_key: usize,
        bandwidth_initial_distribution_primitives_kem_ct: usize,
        bandwidth_initial_distribution_primitives_olm_overhead: usize,
        bandwidth_rotation_primitives_megolm_key: usize,
        bandwidth_rotation_primitives_ratchet_key: usize,
        bandwidth_rotation_primitives_kem_ct: usize,
        bandwidth_rotation_primitives_olm_overhead: usize,
    }

    let mut wtr = csv::Writer::from_path(filename)?;

    for run in runs {
        for room in &run.rooms {
            wtr.serialize(CsvRow {
                batch_id: &run.batch_id,
                pair_id: &run.pair_id,
                repeat_id: run.repeat_id,
                user_profile: &run.user_profile,
                room_id: &room.room_id,
                room_type: &room.room_type,
                member_count: room.member_count,
                crypto_mode: &room.crypto_mode,
                room_creation_ms: room.room_creation_ms,
                add_members_ms: room.add_members_ms,
                session_setup_ms: room.session_setup_ms,
                message_encrypt_ms: room.message_encrypt_ms,
                message_encrypt_pure_ms: room.message_encrypt_pure_ms,
                message_decrypt_ms: room.message_decrypt_ms,
                total_setup_ms: room.total_setup_ms,
                setup_time_ms: room.setup_time_ms,
                rotation_time_ms: room.rotation_time_ms,
                encrypt_steady_state_ms: room.encrypt_steady_state_ms,
                device_type: &room.device_type,
                architecture: &room.architecture,
                cpu_cores: room.cpu_cores,
                cpu_freq_mhz: room.cpu_freq_mhz,
                rotation_policy: &room.rotation_policy,
                actual_rotations: room.actual_rotations,
                kem_handshake_bytes: room.kem_handshake_bytes,
                olm_session_bytes: room.olm_session_bytes,
                megolm_session_bytes: room.megolm_session_bytes,
                message_overhead_bytes: room.message_overhead_bytes,
                total_bandwidth_bytes: room.total_bandwidth_bytes,
                num_ratchet_advances: room.num_ratchet_advances,
                num_asymmetric_advances: room.num_asymmetric_advances,
                num_rotation_messages: room.num_rotation_messages,
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
                bandwidth_control_plane: room.bandwidth_control_plane,
                bandwidth_data_plane: room.bandwidth_data_plane,
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
            })?;
        }
    }

    wtr.flush()?;
    progress!(" Dados pareados (long/tidy) salvos: {}", filename);
    progress!("  (Formato: cada linha = uma sala em uma repetição)");
    progress!("  (Análise: python scripts/analyze.py {})", filename);
    Ok(())
}
