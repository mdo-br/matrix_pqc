//! Módulo de workload realista para simulação de cenários Matrix
//!
//! Implementa workloads baseados em estudos acadêmicos sobre aplicações
//! de mensagens instantâneas (WhatsApp, Telegram, WeChat, etc).
//!
//! # Fundamentos Acadêmicos
//!
//! Implementações baseadas em:
//!
//! 1. Seufert et al. (2023) - "Share and Multiply: Modeling Communication 
//!    and Generated Traffic in Private WhatsApp Groups".
//!    DOI: https://doi.org/10.1109/ACCESS.2023.3254913
//!    - Dataset: 76M mensagens de 117K usuários
//!    - Análise de grupos privados e padrões multiplicativos
//!
//! 2. Seufert et al. (2015) - "Analysis of Group-Based Communication in WhatsApp"
//!    DOI: https://doi.org/10.1007/978-3-319-26925-2_17
//!    - Caracterização empírica de chats em grupo
//!    - Modelagem com processo semi-Markov
//!
//! 3. Keshvadi et al. (2020) - "Traffic Characterization of 
//!    Instant Messaging Apps: A Campus-Level View"
//!    DOI: https://doi.org/10.1109/LCN48667.2020.9314799
//!    - Análise de Facebook Messenger, WeChat, Snapchat
//!    - Padrões diurnos com picos de rajada
//!
//! 4. Rammos et al. (2021) - "The Impact of Instant Messaging on the 
//!    Energy Consumption of Android Devices"
//!    DOI: https://doi.org/10.1109/MobileSoft52590.2021.00007
//!    - Estudo empírico WhatsApp/Telegram
//!    - Modo burst vs. regular (10 msg/min vs. 50 msg/min)
//!
//! # Parâmetros Realistas
//!
//! - Distribuição de tipos de mensagem baseada em observações empíricas
//! - Padrões de tráfego temporal (constante, rajada, periódico, realista)
//! - Cenários de uso diferenciados (chat pequeno, grupo médio, canal grande)
//! - Rotação de chaves baseada em cenários de uso real Matrix/Element
//! - Tamanhos de mensagem realistas para texto, imagem, arquivo e voz

#![allow(dead_code)]


use rand::Rng;
use std::time::Duration;

/// Tipos de mensagens simuladas no experimento
///
/// Baseado em estudos empíricos sobre distribuição de conteúdo
/// em aplicativos de mensagens instantâneas.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageType {
    /// Mensagem textual (70-90% do tráfego)
    Text(String),
    /// Imagem compartilhada (5-25% do tráfego)
    Image(Vec<u8>),
    /// Arquivo anexado (5-10% do tráfego)
    File(Vec<u8>),
    /// Mensagem de sistema/notificação (1-5% do tráfego)
    System(String),
    /// Mensagem de voz (1-5% do tráfego)
    Voice(Vec<u8>),
}

/// Padrões de tráfego para simular comportamentos de envio
///
/// Implementados conforme literatura sobre análise de tráfego
/// de mensageiros instantâneos (Keshvadi et al., Rammos et al.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficPattern {
    /// Tráfego constante com intervalos regulares
    /// Uso: testes de baseline, traffic sintético
    Constant,
    
    /// Picos de atividade (burst mode)
    /// Baseado em Rammos et al. (2021): 50 msg/min com pausas
    /// Uso: simular conversas intensas, sharestorms
    Burst,
    
    /// Atividade periódica (heartbeat, notificações)
    /// Uso: canais de sistema, bots
    Periodic,
    
    /// Tráfego aleatório com distribuição uniforme
    /// Uso: testes de robustez
    Random,
    
    /// Combinação de padrões reais
    /// Baseado em observações empíricas de uso real
    /// Uso: experimentos realistas
    Realistic,
}

/// Cenários de uso para diferentes tipos de salas/canais Matrix
///
/// Parametrização baseada em estudos de grupos WhatsApp
/// (Seufert et al. 2015, 2023) e Matrix Element usage patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageScenario {
    /// Sala pequena: chat P2P ou grupo pequeno (2-10 usuários)
    /// ~100 mensagens típicas, rotação a cada 100 msgs
    /// Distribuição: 85% texto, 12% imagem, 3% voz
    SmallChat,
    
    /// Grupo médio: 20-50 usuários
    /// ~250 mensagens típicas, rotação a cada 250 msgs
    /// Distribuição: 70% texto, 25% imagem, 5% arquivo
    MediumGroup,
    
    /// Canal grande: 100+ usuários
    /// ~250 mensagens típicas, rotação a cada 250 msgs
    /// Distribuição: 75% texto, 15% imagem, 10% arquivo
    LargeChannel,
    
    /// Canal de sistema: notificações, logs
    /// ~1000 mensagens típicas, rotação a cada 1000 msgs
    /// Distribuição: 90% sistema, 10% texto
    SystemChannel,
}

impl UsageScenario {
    /// Retorna número típico de mensagens para este cenário
    pub fn typical_message_count(&self) -> usize {
        match self {
            UsageScenario::SmallChat => 100,
            UsageScenario::MediumGroup => 250,
            UsageScenario::LargeChannel => 500,
            UsageScenario::SystemChannel => 1000,
        }
    }
    
    /// Retorna intervalo de rotação de chaves Megolm (em número de mensagens)
    /// Configurado para ter múltiplas rotações e medir overhead da catraca assimétrica
    /// ATUALIZADO: Distribuição balanceada das 3 políticas (Paranoid/Balanced/Relaxed)
    pub fn rotation_interval(&self) -> usize {
        match self {
            UsageScenario::SmallChat => 50,       // 100 msgs → 2 rotações (Paranoid ≤50)
            UsageScenario::MediumGroup => 100,    // 250 msgs → 2 rotações (Balanced ≤100)
            UsageScenario::LargeChannel => 250,   // 500 msgs → 2 rotações (Relaxed >100)
            UsageScenario::SystemChannel => 250,  // 1000 msgs → 4 rotações (Relaxed >100)
        }
    }
}

/// Configuração de workload para um experimento
#[derive(Debug, Clone)]
pub struct WorkloadConfig {
    /// Cenário de uso a ser simulado
    pub scenario: UsageScenario,
    /// Padrão de tráfego a ser utilizado
    pub pattern: TrafficPattern,
    /// Número total de mensagens a serem geradas
    pub message_count: usize,
    /// Intervalo de rotação de chaves Megolm (em mensagens)
    pub rotation_interval: usize,
}

impl WorkloadConfig {
    /// Cria nova configuração com valores padrão para o cenário
    pub fn new(scenario: UsageScenario, pattern: TrafficPattern) -> Self {
        Self {
            scenario,
            pattern,
            message_count: scenario.typical_message_count(),
            rotation_interval: scenario.rotation_interval(),
        }
    }
    
    /// Cria configuração customizada
    pub fn custom(
        scenario: UsageScenario,
        pattern: TrafficPattern,
        message_count: usize,
        rotation_interval: usize,
    ) -> Self {
        Self {
            scenario,
            pattern,
            message_count,
            rotation_interval,
        }
    }
}

/// Gerador de mensagens realistas baseado em cenário
///
/// Implementa distribuições de tipos de mensagem conforme
/// estudos empíricos de WhatsApp, WeChat e Matrix.
pub struct MessageGenerator {
    scenario: UsageScenario,
    rng: rand::rngs::StdRng,
}

impl MessageGenerator {
    /// Cria novo gerador para um cenário específico com seed aleatória
    pub fn new(scenario: UsageScenario) -> Self {
        use rand::SeedableRng;
        Self {
            scenario,
            rng: rand::rngs::StdRng::from_entropy(),
        }
    }
    
    /// Cria novo gerador com seed fixa (para reprodutibilidade)
    pub fn new_with_seed(scenario: UsageScenario, seed: u64) -> Self {
        use rand::SeedableRng;
        Self {
            scenario,
            rng: rand::rngs::StdRng::seed_from_u64(seed),
        }
    }
    
    /// Gera uma mensagem realista baseada no cenário
    ///
    /// A distribuição dos tipos de mensagem depende do cenário,
    /// baseada em estudos empíricos (Seufert et al., Deng et al.).
    pub fn generate_message(&mut self) -> MessageType {
        let rand_val: f64 = self.rng.gen_range(0.0..1.0);
        
        match self.scenario {
            UsageScenario::SmallChat => {
                // Chat P2P/pequenos grupos: alta proporção de texto
                // Seufert et al. (2015): grupos pequenos ~85% texto
                if rand_val < 0.85 {
                    MessageType::Text(self.generate_text_message())
                } else if rand_val < 0.97 {
                    MessageType::Image(self.generate_image_message())
                } else {
                    MessageType::Voice(self.generate_voice_message())
                }
            }
            
            UsageScenario::MediumGroup => {
                // Grupos médios: mais compartilhamento de mídia
                // Distribuição: 70% texto, 25% imagem, 5% arquivo
                if rand_val < 0.70 {
                    MessageType::Text(self.generate_text_message())
                } else if rand_val < 0.95 {
                    MessageType::Image(self.generate_image_message())
                } else {
                    MessageType::File(self.generate_file_message())
                }
            }
            
            UsageScenario::LargeChannel => {
                // Canais grandes: mix equilibrado
                // Distribuição: 75% texto, 15% imagem, 10% arquivo
                if rand_val < 0.75 {
                    MessageType::Text(self.generate_text_message())
                } else if rand_val < 0.90 {
                    MessageType::Image(self.generate_image_message())
                } else {
                    MessageType::File(self.generate_file_message())
                }
            }
            
            UsageScenario::SystemChannel => {
                // Canais de sistema: predominância de notificações
                // Distribuição: 90% sistema, 10% texto
                if rand_val < 0.90 {
                    MessageType::System(self.generate_system_message())
                } else {
                    MessageType::Text(self.generate_text_message())
                }
            }
        }
    }
    
    /// Gera conteúdo de mensagem de texto (50-500 bytes)
    fn generate_text_message(&mut self) -> String {
        let size = self.rng.gen_range(50..500);
        "A".repeat(size)
    }
    
    /// Gera conteúdo de imagem (10KB-500KB)
    fn generate_image_message(&mut self) -> Vec<u8> {
        let size = self.rng.gen_range(10_000..500_000);
        vec![0u8; size]
    }
    
    /// Gera conteúdo de arquivo (100KB-5MB)
    fn generate_file_message(&mut self) -> Vec<u8> {
        let size = self.rng.gen_range(100_000..5_000_000);
        vec![0u8; size]
    }
    
    /// Gera conteúdo de voz (10KB-200KB)
    fn generate_voice_message(&mut self) -> Vec<u8> {
        let size = self.rng.gen_range(10_000..200_000);
        vec![0u8; size]
    }
    
    /// Gera mensagem de sistema (20-100 bytes)
    fn generate_system_message(&mut self) -> String {
        let size = self.rng.gen_range(20..100);
        format!("[SYSTEM] {}", "X".repeat(size))
    }
    
    /// Converte mensagem para bytes (para cifra)
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

/// Gerador de padrões de tráfego temporal
///
/// Implementa diferentes padrões baseados em estudos de
/// traffic characterization (Keshvadi et al., Rammos et al.).
pub struct TrafficGenerator {
    pattern: TrafficPattern,
    message_count: usize,
    current_index: usize,
    rng: rand::rngs::ThreadRng,
}

impl TrafficGenerator {
    /// Cria novo gerador de tráfego
    pub fn new(pattern: TrafficPattern, message_count: usize) -> Self {
        Self {
            pattern,
            message_count,
            current_index: 0,
            rng: rand::thread_rng(),
        }
    }
    
    /// Retorna próximo intervalo de tempo até enviar mensagem
    ///
    /// Retorna `None` quando todas as mensagens foram geradas.
    pub fn next_interval(&mut self) -> Option<Duration> {
        if self.current_index >= self.message_count {
            return None;
        }
        
        self.current_index += 1;
        
        let interval_ms = match self.pattern {
            TrafficPattern::Constant => {
                // Intervalo fixo: 100ms entre mensagens
                100
            }
            
            TrafficPattern::Burst => {
                // Burst mode (Rammos et al. 2021): 50 msg/min = 1200ms/msg
                // Mas em rajadas: 50ms durante burst, pausa 500ms a cada 50 msgs
                if self.current_index % 50 == 0 {
                    500 // Pausa entre bursts
                } else {
                    20  // Rápido dentro do burst
                }
            }
            
            TrafficPattern::Periodic => {
                // Padrão periódico: alternância 50ms / 200ms
                if self.current_index % 2 == 0 {
                    50
                } else {
                    200
                }
            }
            
            TrafficPattern::Random => {
                // Intervalo aleatório: 10-500ms
                self.rng.gen_range(10..500)
            }
            
            TrafficPattern::Realistic => {
                // Mix de padrões: 70% constante, 20% burst, 10% pausa longa
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
    
    /// Retorna se ainda há mensagens a serem geradas
    pub fn has_next(&self) -> bool {
        self.current_index < self.message_count
    }
    
    /// Retorna progresso atual (0.0 a 1.0)
    pub fn progress(&self) -> f64 {
        self.current_index as f64 / self.message_count as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_usage_scenario_defaults() {
        assert_eq!(UsageScenario::SmallChat.typical_message_count(), 100);
        assert_eq!(UsageScenario::MediumGroup.typical_message_count(), 250);
        assert_eq!(UsageScenario::LargeChannel.typical_message_count(), 500);
        assert_eq!(UsageScenario::SystemChannel.typical_message_count(), 1000);
    }
    
    #[test]
    fn test_workload_config_new() {
        let config = WorkloadConfig::new(
            UsageScenario::SmallChat,
            TrafficPattern::Constant
        );
        assert_eq!(config.message_count, 100);
        assert_eq!(config.rotation_interval, 50);  // SmallChat usa Paranoid (50)
    }
    
    #[test]
    fn test_message_generator() {
        let mut gen = MessageGenerator::new(UsageScenario::SmallChat);
        
        // Gerar 100 mensagens e verificar distribuição aproximada
        let mut text_count = 0;
        let mut image_count = 0;
        
        for _ in 0..100 {
            match gen.generate_message() {
                MessageType::Text(_) => text_count += 1,
                MessageType::Image(_) => image_count += 1,
                _ => {}
            }
        }
        
        // SmallChat deveria ter ~85% texto
        assert!(text_count > 70, "Esperado >70% texto, obteve {}%", text_count);
        // Teste probabilístico: aceitar >= 4% devido à variância estatística com n=100
        assert!(image_count >= 4, "Esperado >=4% imagem, obteve {}%", image_count);
    }
    
    #[test]
    fn test_traffic_generator() {
        let mut gen = TrafficGenerator::new(TrafficPattern::Constant, 10);
        
        assert!(gen.has_next());
        assert_eq!(gen.progress(), 0.0);
        
        // Consumir todas as mensagens
        let mut count = 0;
        while gen.next_interval().is_some() {
            count += 1;
        }
        
        assert_eq!(count, 10);
        assert!(!gen.has_next());
        assert_eq!(gen.progress(), 1.0);
    }
}
