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
