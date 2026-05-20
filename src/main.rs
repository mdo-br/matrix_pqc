// Vodozemac Wrapper PQC — user profile benchmark.

use anyhow::Result;
use clap::{Parser, ValueEnum};

mod core;
mod protocols;
mod benchmark;
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
#[command(about = "Vodozemac Wrapper PQC — user profile benchmark", long_about = None)]
struct Args {
    /// Operation mode.
    #[arg(long, value_enum, default_value = "user-profile")]
    mode: Mode,

    /// Number of benchmark repetitions.
    #[arg(long, default_value_t = 5)]
    repetitions: usize,

    /// Run all rotation policies.
    #[arg(long, default_value_t = false)]
    all_rotation_policies: bool,

    /// Specific rotation policy (ignored when --all-rotation-policies is set).
    #[arg(long, value_enum)]
    rotation_policy: Option<RotationPolicyArg>,

    /// Verbosity level (0=Silent, 1=Minimal, 2=Normal, 3=Verbose, 4=Debug).
    #[arg(long, default_value_t = 2)]
    verbosity: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Configure verbosity.
    use utils::logging::{set_verbosity, VerbosityLevel};
    let verbosity = match args.verbosity {
        0 => VerbosityLevel::Silent,
        1 => VerbosityLevel::Minimal,
        2 => VerbosityLevel::Normal,
        3 => VerbosityLevel::Verbose,
        _ => VerbosityLevel::Debug,
    };
    set_verbosity(verbosity);

    progress!("=== Vodozemac Wrapper PQC ===\n");

    match args.mode {
        Mode::UserProfile => run_user_profile_benchmark(&args)?,
    }

    Ok(())
}

fn run_user_profile_benchmark(args: &Args) -> Result<()> {
    use benchmark::{run_paired_benchmark, save_paired_runs_csv};
    use chrono::Local;
    use utils::logging::VerbosityLevel;

    let user_id = "@alice:matrix.org";
    let repetitions = args.repetitions;

    if args.all_rotation_policies {
        progress!("Running ALL rotation policies ({} repetitions each)\n", repetitions);
        
        std::fs::create_dir_all("results")?;
        
        let policies = vec![
            RotationPolicyArg::Paranoid,
            RotationPolicyArg::PQ3,
            RotationPolicyArg::Balanced,
            RotationPolicyArg::Relaxed,
        ];

        // Collect all paired runs across all policies.
        let mut all_paired_runs = Vec::new();

        // Run each policy.
        for (policy_idx, policy_arg) in policies.iter().enumerate() {
            let policy = policy_arg.to_protocol_policy();
            
            vlog!(VerbosityLevel::Normal, "\n--- Running policy: {:?} [{}/{}] ---", 
                     policy_arg, policy_idx + 1, policies.len());
            
            let paired_runs = run_paired_benchmark(user_id, repetitions, Some(policy))?;
            
            // Merge into consolidated collection.
            all_paired_runs.extend(paired_runs);
            
            vlog!(VerbosityLevel::Verbose, " Policy {:?} done", policy_arg);
        }

        let timestamp = Local::now().timestamp();
        let filename = format!("results/resultados_experiment_{}.csv", timestamp);
        save_paired_runs_csv(&all_paired_runs, &filename)?;

        progress!("\n=== Benchmark Complete ===");
        progress!(" Runs: {} Classical↔Hybrid pairs per policy", repetitions);
        progress!(" Policies: {} (Paranoid, PQ3, Balanced, Relaxed)", policies.len());
        progress!(" Total records: {}", all_paired_runs.len());
        progress!(" CSV: {}", filename);
    } else {
        let policy = args.rotation_policy.map(|p| p.to_protocol_policy());
        let policy_name = match args.rotation_policy {
            Some(p) => format!("{:?}", p),
            None => "All".to_string(),
        };
        
        progress!("Policy: {} ({} repetitions)\n", policy_name, repetitions);
        
        let results = run_paired_benchmark(user_id, repetitions, policy)?;
        
        let timestamp = Local::now().timestamp();
        let filename = format!("results/resultados_experiment_{}.csv", timestamp);
        save_paired_runs_csv(&results, &filename)?;
        
        progress!("\n Saved: {}", filename);
    }

    progress!("\nBenchmark complete.");
    Ok(())
}
