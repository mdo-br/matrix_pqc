// Vodozemac Wrapper PQC
// Benchmark de Perfil de Usuário

use anyhow::Result;
use clap::{Parser, ValueEnum};

mod core;
mod protocols;
mod demos;
mod tools;
mod utils;

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum Mode {
    UserProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum RotationPolicyArg {
    Paranoid,
    PQ3,
    Balanced,
    Relaxed,
}

impl RotationPolicyArg {
    fn to_protocol_policy(&self) -> protocols::room::RotationPolicy {
        match self {
            RotationPolicyArg::Paranoid => protocols::room::RotationPolicy::Paranoid,
            RotationPolicyArg::PQ3 => protocols::room::RotationPolicy::PQ3,
            RotationPolicyArg::Balanced => protocols::room::RotationPolicy::Balanced,
            RotationPolicyArg::Relaxed => protocols::room::RotationPolicy::Relaxed,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "vodozemac-wrapper-pqc")]
#[command(about = "Vodozemac Wrapper PQC - Benchmark de Perfil de Usuário", long_about = None)]
struct Args {
    /// Modo de operação
    #[arg(long, value_enum, default_value = "user-profile")]
    mode: Mode,

    /// Número de repetições do benchmark
    #[arg(long, default_value_t = 5)]
    repetitions: usize,

    /// Testar todas as políticas de rotação
    #[arg(long, default_value_t = false)]
    all_rotation_policies: bool,

    /// Política de rotação específica (ignorado se --all-rotation-policies)
    #[arg(long, value_enum)]
    rotation_policy: Option<RotationPolicyArg>,

    /// Nível de verbosidade (0=Silent, 1=Minimal, 2=Normal, 3=Verbose, 4=Debug)
    #[arg(long, default_value_t = 2)]
    verbosity: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Configurar verbosidade
    use utils::logging::{set_verbosity, VerbosityLevel};
    let verbosity = match args.verbosity {
        0 => VerbosityLevel::Silent,
        1 => VerbosityLevel::Minimal,
        2 => VerbosityLevel::Normal,
        3 => VerbosityLevel::Verbose,
        _ => VerbosityLevel::Debug,
    };
    set_verbosity(verbosity);

    println!("=== Vodozemac Wrapper PQC ===\n");

    match args.mode {
        Mode::UserProfile => run_user_profile_benchmark(&args)?,
    }

    Ok(())
}

fn run_user_profile_benchmark(args: &Args) -> Result<()> {
    use demos::user_profile_benchmark::{run_paired_benchmark, save_paired_runs_csv};
    use chrono::Local;

    let user_id = "@alice:matrix.org";
    let repetitions = args.repetitions;

    if args.all_rotation_policies {
        println!("Testando TODAS as políticas de rotação ({} repetições cada)\n", repetitions);
        
        std::fs::create_dir_all("results")?;
        
        let policies = vec![
            RotationPolicyArg::Paranoid,
            RotationPolicyArg::PQ3,
            RotationPolicyArg::Balanced,
            RotationPolicyArg::Relaxed,
        ];

        // Coletar todos os runs de todas as políticas
        let mut all_paired_runs = Vec::new();

        // Executar para cada política
        for (policy_idx, policy_arg) in policies.iter().enumerate() {
            let policy = policy_arg.to_protocol_policy();
            
            println!("\n--- Executando com política: {:?} [{}/{}] ---", 
                     policy_arg, policy_idx + 1, policies.len());
            
            let paired_runs = run_paired_benchmark(user_id, repetitions, Some(policy))?;
            
            // Adicionar à coleção consolidada
            all_paired_runs.extend(paired_runs);
            
            println!(" Política {:?} concluída", policy_arg);
        }

        // Salvar TODOS os runs em um único CSV
        let timestamp = Local::now().timestamp();
        let filename = format!("results/resultados_experiment_{}.csv", timestamp);
        save_paired_runs_csv(&all_paired_runs, &filename)?;

        println!("\n=== Benchmark Concluído ===");
        println!(" Execuções: {} pares Classical↔Hybrid por política", repetitions);
        println!(" Políticas executadas: {} (Paranoid, PQ3, Balanced, Relaxed)", policies.len());
        println!(" Total de registros: {}", all_paired_runs.len());
        println!(" CSV consolidado: {}", filename);
        println!("   (Todas as políticas em um único arquivo)");
    } else {
        let policy = args.rotation_policy.map(|p| p.to_protocol_policy());
        let policy_name = match args.rotation_policy {
            Some(p) => format!("{:?}", p),
            None => "All".to_string(),
        };
        
        println!("Política: {} ({} repetições)\n", policy_name, repetitions);
        
        let results = run_paired_benchmark(user_id, repetitions, policy)?;
        
        let timestamp = Local::now().timestamp();
        let filename = format!("results/resultados_experiment_{}.csv", timestamp);
        save_paired_runs_csv(&results, &filename)?;
        
        println!("\n Salvos: {}", filename);
    }

    println!("\nBenchmark concluído com sucesso!");
    Ok(())
}
