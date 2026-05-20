//! Realistic workload generator for Matrix scenario simulations.
//!
//! Message type distributions and traffic patterns are derived from
//! empirical studies of instant messaging applications:
//!
//! 1. Seufert et al. (2023) - "Share and Multiply: Modeling Communication 
//!    and Generated Traffic in Private WhatsApp Groups".
//!    DOI: https://doi.org/10.1109/ACCESS.2023.3254913
//!    - Analyse private groups and multiplicative patterns 
//!
//! 2. Seufert et al. (2015) - "Analysis of Group-Based Communication in WhatsApp"
//!    DOI: https://doi.org/10.1007/978-3-319-26925-2_17
//!    - Empirical characterization of group chats 
//!    - Modeling with semi-Markov process
//!
//! 3. Keshvadi et al. (2020) - "Traffic Characterization of 
//!    Instant Messaging Apps: A Campus-Level View"
//!    DOI: https://doi.org/10.1109/LCN48667.2020.9314799
//!    - Analysis of Facebook Messenger, WeChat, Snapchat
//!    - Diurnal patterns with burst peaks
//!
//! 4. Rammos et al. (2021) - "The Impact of Instant Messaging on the 
//!    Energy Consumption of Android Devices"
//!    DOI: https://doi.org/10.1109/MobileSoft52590.2021.00007
//!    - Empirical study of WhatsApp/Telegram
//!    - Burst vs. regular mode (10 msg/min vs. 50 msg/min)
//!
//! # Realistic Parameters
//!
//! - Message type distribution based on empirical observations
//! - Temporal traffic patterns (constant, burst, periodic, realistic)
//! - Different usage scenarios (small chat, medium group, large channel)
//! - Key rotation based on real-world usage scenarios Matrix/Element
//! - Realistic message sizes for text, images, files and voice

#![allow(dead_code)]


use rand::Rng;
use std::time::Duration;

/// Message types simulated in the experiment.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageType {
    Text(String),
    Image(Vec<u8>),
    File(Vec<u8>),
    System(String),
    Voice(Vec<u8>),
}

/// Traffic patterns for simulating message sending behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficPattern {
    /// Steady traffic at regular intervals.
    Constant,
    /// Short activity bursts followed by silence (Rammos et al. 2021: 50 msg/min).
    Burst,
    /// Periodic heartbeat (system channels, bots).
    Periodic,
    /// Uniformly random inter-arrival times.
    Random,
    /// Combination of burst and regular patterns based on empirical observations.
    Realistic,
}

/// Room types used to parameterise workload scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageScenario {
    /// Small chat: P2P or small group (2–10 users), ~100 messages, rotation every 100 msgs.
    SmallChat,
    /// Medium group: 20–50 users, ~250 messages, rotation every 250 msgs.
    MediumGroup,
    /// Large channel: 100+ users, ~500 messages, rotation every 500 msgs.
    LargeChannel,
    /// System channel: notifications/logs, ~1000 messages, rotation every 1000 msgs.
    SystemChannel,
}

impl UsageScenario {
    pub fn typical_message_count(&self) -> usize {
        match self {
            UsageScenario::SmallChat => 100,
            UsageScenario::MediumGroup => 250,
            UsageScenario::LargeChannel => 500,
            UsageScenario::SystemChannel => 1000,
        }
    }
    
    pub fn rotation_interval(&self) -> usize {
        match self {
            UsageScenario::SmallChat => 50,
            UsageScenario::MediumGroup => 100,
            UsageScenario::LargeChannel => 250,
            UsageScenario::SystemChannel => 250,
        }
    }
}

/// Workload configuration for a single experiment run.
#[derive(Debug, Clone)]
pub struct WorkloadConfig {
    pub scenario: UsageScenario,
    pub pattern: TrafficPattern,
    pub message_count: usize,
    pub rotation_interval: usize,
}

impl WorkloadConfig {
    pub fn new(scenario: UsageScenario, pattern: TrafficPattern) -> Self {
        Self {
            scenario,
            pattern,
            message_count: scenario.typical_message_count(),
            rotation_interval: scenario.rotation_interval(),
        }
    }
    
    pub fn custom(
        scenario: UsageScenario,
        pattern: TrafficPattern,
        message_count: usize,
        rotation_interval: usize,
    ) -> Self {
        Self { scenario, pattern, message_count, rotation_interval }
    }
}

/// Generates realistic Matrix messages for a given usage scenario.
pub struct MessageGenerator {
    scenario: UsageScenario,
    rng: rand::rngs::StdRng,
}

impl MessageGenerator {
    pub fn new(scenario: UsageScenario) -> Self {
        use rand::SeedableRng;
        Self { scenario, rng: rand::rngs::StdRng::from_entropy() }
    }
    
    pub fn new_with_seed(scenario: UsageScenario, seed: u64) -> Self {
        use rand::SeedableRng;
        Self { scenario, rng: rand::rngs::StdRng::seed_from_u64(seed) }
    }
    
    /// Generates a message whose type is sampled from the scenario's empirical distribution.
    pub fn generate_message(&mut self) -> MessageType {
        let rand_val: f64 = self.rng.gen_range(0.0..1.0);
        
        match self.scenario {
            UsageScenario::SmallChat => {
                if rand_val < 0.85 {
                    MessageType::Text(self.generate_text_message())
                } else if rand_val < 0.97 {
                    MessageType::Image(self.generate_image_message())
                } else {
                    MessageType::Voice(self.generate_voice_message())
                }
            }
            
            UsageScenario::MediumGroup => {
                if rand_val < 0.70 {
                    MessageType::Text(self.generate_text_message())
                } else if rand_val < 0.95 {
                    MessageType::Image(self.generate_image_message())
                } else {
                    MessageType::File(self.generate_file_message())
                }
            }
            
            UsageScenario::LargeChannel => {
                if rand_val < 0.75 {
                    MessageType::Text(self.generate_text_message())
                } else if rand_val < 0.90 {
                    MessageType::Image(self.generate_image_message())
                } else {
                    MessageType::File(self.generate_file_message())
                }
            }
            
            UsageScenario::SystemChannel => {
                if rand_val < 0.90 {
                    MessageType::System(self.generate_system_message())
                } else {
                    MessageType::Text(self.generate_text_message())
                }
            }
        }
    }
    
    /// Generates text message content (50–500 bytes).
    fn generate_text_message(&mut self) -> String {
        let size = self.rng.gen_range(50..500);
        "A".repeat(size)
    }
    
    /// Generates image message content (10 KB–500 KB).
    fn generate_image_message(&mut self) -> Vec<u8> {
        let size = self.rng.gen_range(10_000..500_000);
        vec![0u8; size]
    }
    
    /// Generates file message content (100 KB–5 MB).
    fn generate_file_message(&mut self) -> Vec<u8> {
        let size = self.rng.gen_range(100_000..5_000_000);
        vec![0u8; size]
    }
    
    /// Generates voice message content (10 KB–200 KB).
    fn generate_voice_message(&mut self) -> Vec<u8> {
        let size = self.rng.gen_range(10_000..200_000);
        vec![0u8; size]
    }
    
    /// Generates a system message (20–100 bytes).
    fn generate_system_message(&mut self) -> String {
        let size = self.rng.gen_range(20..100);
        format!("[SYSTEM] {}", "X".repeat(size))
    }
    
    /// Converts a message to its raw byte representation.
    pub fn message_to_bytes(&self, msg: &MessageType) -> Vec<u8> {
        match msg {
            MessageType::Text(s) => s.as_bytes().to_vec(),
            MessageType::Image(b) => b.clone(),
            MessageType::File(b) => b.clone(),
            MessageType::System(s) => s.as_bytes().to_vec(),
            MessageType::Voice(b) => b.clone(),
        }
    }
}

/// Generates inter-message timing intervals for a given traffic pattern.
///
/// Implements traffic models from Keshvadi et al. and Rammos et al.
pub struct TrafficGenerator {
    pattern: TrafficPattern,
    message_count: usize,
    current_index: usize,
    rng: rand::rngs::ThreadRng,
}

impl TrafficGenerator {
    /// Creates a new traffic generator for the given pattern and total message count.
    pub fn new(pattern: TrafficPattern, message_count: usize) -> Self {
        Self {
            pattern,
            message_count,
            current_index: 0,
            rng: rand::thread_rng(),
        }
    }
    
    /// Returns the next inter-message interval, or `None` when all messages have been generated.
    pub fn next_interval(&mut self) -> Option<Duration> {
        if self.current_index >= self.message_count {
            return None;
        }
        
        self.current_index += 1;
        
        let interval_ms = match self.pattern {
            TrafficPattern::Constant => {
                100
            }
            
            TrafficPattern::Burst => {
                // Burst mode (Rammos et al. 2021): rapid sends within bursts, pause every 50 messages.
                if self.current_index % 50 == 0 {
                    500 // inter-burst pause
                } else {
                    20  // intra-burst
                }
            }
            
            TrafficPattern::Periodic => {
                // Periodic Pattern: 50ms / 200ms
                if self.current_index % 2 == 0 {
                    50
                } else {
                    200
                }
            }
            
            TrafficPattern::Random => {
                self.rng.gen_range(10..500)
            }
            
            TrafficPattern::Realistic => {
                // Mix: 70% constant, 20% burst, 10% long pause.
                let rand_val: f64 = self.rng.gen_range(0.0..1.0);
                if rand_val < 0.70 {
                    100  // Constante
                } else if rand_val < 0.90 {
                    20   // Burst
                } else {
                    500  // Pausa longa
                }
            }
        };
        
        Some(Duration::from_millis(interval_ms))
    }
    
    /// Returns `true` if there are more messages to generate.
    pub fn has_next(&self) -> bool {
        self.current_index < self.message_count
    }
    
    /// Returns generation progress in [0.0, 1.0].
    pub fn progress(&self) -> f64 {
        self.current_index as f64 / self.message_count as f64
    }
}
