// Módulo de benchmark de desempenho PQC
//
// Unifica a orquestração de experimentos (antes em demos/) e as
// distribuições de carga de trabalho (antes em tools/).

pub mod metrics;
pub mod runner;
pub mod workload;

#[allow(unused_imports)]
pub use metrics::{
    HardwareProfile, RotationMetrics, BandwidthMetrics,
    RoomType, UserProfile,
    RoomBenchmark, ProfileBenchmark, PairedRun,
};
#[allow(unused_imports)]
pub use runner::{benchmark_room, run_paired_benchmark, save_paired_runs_csv};
#[allow(unused_imports)]
pub use workload::{MessageType, TrafficPattern, UsageScenario, WorkloadConfig,
                   MessageGenerator, TrafficGenerator};
