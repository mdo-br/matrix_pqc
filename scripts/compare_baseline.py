#!/usr/bin/env python3
"""
Compara dois experimentos user-profile para detectar regressões de performance.
Usado para validar mudanças no código (ex: Kyber Round 3 -> ML-KEM FIPS 203).

MÉTRICAS EXPLICADAS:
- total_setup_ms: Tempo TOTAL de setup (criação sala + adicionar membros + handshakes)
- session_setup_ms: Apenas handshakes criptográficos (PQXDH/Olm + distribuição Megolm)
- message_encrypt_ms: Criptografia COM overhead (rotações, gerenciamento, estado)
- message_encrypt_pure_ms: Criptografia PURA (apenas Megolm AES-256, sem overhead)
- message_decrypt_ms: Decriptografia de mensagens Megolm

FASES DO PROTOCOLO:
1. SETUP (session_setup_ms):
   - Handshakes PQXDH (ML-KEM-1024 + Curve25519)
   - Criação de sessões Megolm outbound
   - Distribuição inicial de chaves via Olm
   
2. ROTAÇÃO (incluído em message_encrypt_ms):
   - Criação de nova sessão Megolm
   - Redistribuição via Olm para todos os membros
   - Ratcheting assimétrico das sessões Olm
   
3. STEADY-STATE (message_encrypt_pure_ms):
   - Apenas criptografia AES-256-CTR (Megolm)
   - Sem overhead de gerenciamento ou rotações
"""

import sys
import pandas as pd
import numpy as np
from scipy import stats

def load_and_prepare(csv_path):
    """Carrega CSV e prepara dados agregados por sala."""
    df = pd.read_csv(csv_path)
    
    # Agregar por sala (média de repetições)
    agg_funcs = {
        'total_setup_ms': 'mean',
        'session_setup_ms': 'mean',
        'message_encrypt_ms': 'mean',
        'message_encrypt_pure_ms': 'mean',
        'message_decrypt_ms': 'mean',
        'kem_handshake_bytes': 'mean',
        'olm_session_bytes': 'mean',
        'megolm_session_bytes': 'mean',
        'total_bandwidth_bytes': 'mean',
    }
    
    grouped = df.groupby(['crypto_mode', 'room_type', 'member_count', 
                          'rotation_policy']).agg(agg_funcs).reset_index()
    
    return grouped

def compare_metric(baseline, current, metric_name, unit='ms'):
    """Compara uma métrica específica entre baseline e current."""
    baseline_mean = baseline[metric_name].mean()
    current_mean = current[metric_name].mean()
    
    # Variação percentual
    if baseline_mean > 0:
        pct_change = ((current_mean - baseline_mean) / baseline_mean) * 100
    else:
        pct_change = 0.0
    
    # Teste t pareado (se possível)
    if len(baseline) == len(current) and len(baseline) > 1:
        try:
            t_stat, p_value = stats.ttest_rel(current[metric_name], baseline[metric_name])
        except:
            p_value = None
    else:
        p_value = None
    
    return {
        'baseline_mean': baseline_mean,
        'current_mean': current_mean,
        'delta': current_mean - baseline_mean,
        'pct_change': pct_change,
        'p_value': p_value
    }

def main():
    if len(sys.argv) != 3:
        print("Uso: python compare_baseline.py <baseline.csv> <current.csv>")
        sys.exit(1)
    
    baseline_path = sys.argv[1]
    current_path = sys.argv[2]
    
    print("=" * 80)
    print("COMPARAÇÃO BASELINE vs. CURRENT")
    print("=" * 80)
    print(f"Baseline: {baseline_path}")
    print(f"Current:  {current_path}")
    print()
    
    # Carregar dados
    baseline = load_and_prepare(baseline_path)
    current = load_and_prepare(current_path)
    
    print(f"Registros baseline: {len(baseline)}")
    print(f"Registros current:  {len(current)}")
    print()
    
    # Filtrar apenas Hybrid para comparação justa
    baseline_hybrid = baseline[baseline['crypto_mode'] == 'Hybrid'].copy()
    current_hybrid = current[current['crypto_mode'] == 'Hybrid'].copy()
    
    print(f"Registros Hybrid baseline: {len(baseline_hybrid)}")
    print(f"Registros Hybrid current:  {len(current_hybrid)}")
    print()
    
    # Métricas de performance críticas
    metrics = [
        ('total_setup_ms', 'ms', 'Setup Total', 
         'Tempo total para preparar sala (criação + membros + handshakes)'),
        ('session_setup_ms', 'ms', 'Setup Sessions', 
         'Apenas handshakes criptográficos (PQXDH + distribuição inicial)'),
        ('message_encrypt_ms', 'ms', 'Encrypt c/ Gerenciamento', 
         'Criptografia COM overhead (rotações, verificações, estado)'),
        ('message_encrypt_pure_ms', 'ms', 'Encrypt Puro', 
         'Criptografia PURA Megolm (AES-256-CTR, sem overhead)'),
        ('message_decrypt_ms', 'ms', 'Decrypt', 
         'Decriptografia de mensagens Megolm (AES-256 + HMAC-SHA-256)'),
    ]
    
    print("=" * 80)
    print("MÉTRICAS DE TEMPO (Performance)")
    print("=" * 80)
    print()
    print("LEGENDA:")
    print("  [SETUP]: Impacto em handshakes iniciais (uma vez por sala)")
    print("  [ROTAÇÃO]: Impacto em redistribuição de chaves (esporádico)")
    print("  [STEADY-STATE]: Impacto em operações contínuas (frequente)")
    print("  Significância: *** p<0.001, ** p<0.01, * p<0.05, n.s. = não significativo")
    print()
    
    for metric, unit, label, description in metrics:
        result = compare_metric(baseline_hybrid, current_hybrid, metric, unit)
        
        # Classificar tipo de fase
        if 'setup' in metric.lower():
            phase_tag = "[SETUP]"
        elif 'encrypt_pure' in metric or 'decrypt' in metric:
            phase_tag = "[STEADY-STATE]"
        else:
            phase_tag = "[ROTAÇÃO]"
        
        # Status
        if abs(result['pct_change']) < 1.0:
            status = "OK - Variação dentro do ruído estatístico"
        elif abs(result['pct_change']) < 5.0:
            status = "ACEITÁVEL - Variação pequena"
        else:
            if result['pct_change'] > 0:
                status = "REGRESSÃO - Investigar causa"
            else:
                status = "MELHORIA - Otimização detectada"
        
        print(f"{phase_tag} {label}:")
        print(f"  Descrição: {description}")
        print(f"  Baseline:  {result['baseline_mean']:.4f} {unit}")
        print(f"  Current:   {result['current_mean']:.4f} {unit}")
        print(f"  Delta:     {result['delta']:+.4f} {unit} ({result['pct_change']:+.2f}%)")
        if result['p_value'] is not None:
            sig = "***" if result['p_value'] < 0.001 else "**" if result['p_value'] < 0.01 else "*" if result['p_value'] < 0.05 else "n.s."
            print(f"  p-value:   {result['p_value']:.6f} {sig}")
        print(f"  Status:    {status}")
        print()
    
    # Métricas de largura de banda (não devem mudar)
    bandwidth_metrics = [
        ('kem_handshake_bytes', 'bytes', 'KEM Handshake',
         'Tamanho do handshake PQXDH (PreKeyMessage)'),
        ('olm_session_bytes', 'bytes', 'OLM Sessions',
         'Tamanho total das sessões Olm estabelecidas'),
        ('megolm_session_bytes', 'bytes', 'Megolm Sessions',
         'Tamanho das sessões Megolm distribuídas'),
    ]
    
    print("=" * 80)
    print("MÉTRICAS DE LARGURA DE BANDA")
    print("=" * 80)
    print()
    print("OBSERVAÇÃO: Largura de banda só muda se o FORMATO dos protocolos mudar.")
    print("            Mudanças de implementação (ex: SHAKE-256 -> HKDF-SHA256) NÃO")
    print("            devem afetar bandwidth. ML-KEM vs Kyber pode ter pequenas")
    print("            diferenças devido a formato FIPS 203 vs Round 3.")
    print()
    
    for metric, unit, label, description in bandwidth_metrics:
        result = compare_metric(baseline_hybrid, current_hybrid, metric, unit)
        
        # Largura de banda - classificar variação
        if abs(result['pct_change']) < 0.01:
            status = "IDÊNTICO - Formato não mudou"
        elif abs(result['pct_change']) < 2.0:
            status = "PEQUENA VARIAÇÃO"
        else:
            status = "DIVERGÊNCIA SIGNIFICATIVA - Investigar"
        
        print(f"{label}:")
        print(f"  Descrição: {description}")
        print(f"  Baseline:  {result['baseline_mean']:.0f} {unit}")
        print(f"  Current:   {result['current_mean']:.0f} {unit}")
        print(f"  Delta:     {result['delta']:+.0f} {unit} ({result['pct_change']:+.2f}%)")
        print(f"  Status:    {status}")
        print()
    
    # Resumo geral
    print("=" * 80)
    print("RESUMO GERAL E INTERPRETAÇÃO")
    print("=" * 80)
    print()
    
    all_metrics = [m[0] for m in metrics]
    all_results = [compare_metric(baseline_hybrid, current_hybrid, m) for m in all_metrics]
    
    avg_pct_change = np.mean([r['pct_change'] for r in all_results])
    max_pct_change = max([abs(r['pct_change']) for r in all_results])
    
    # Separar por fase
    setup_results = [r for m, r in zip(all_metrics, all_results) if 'setup' in m.lower()]
    steady_results = [r for m, r in zip(all_metrics, all_results) 
                      if 'pure' in m or 'decrypt' in m]
    rotation_results = [r for m, r in zip(all_metrics, all_results) 
                        if 'encrypt_ms' in m and 'pure' not in m]
    
    print("VARIAÇÃO POR FASE:")
    if setup_results:
        avg_setup = np.mean([r['pct_change'] for r in setup_results])
        print(f"  [SETUP]:         {avg_setup:+.2f}% (afeta handshakes iniciais)")
    if rotation_results:
        avg_rotation = np.mean([r['pct_change'] for r in rotation_results])
        print(f"  [ROTAÇÃO]:       {avg_rotation:+.2f}% (afeta redistribuição de chaves)")
    if steady_results:
        avg_steady = np.mean([r['pct_change'] for r in steady_results])
        print(f"  [STEADY-STATE]:  {avg_steady:+.2f}% (afeta operações contínuas)")
    print()
    
    print(f"Variação média geral: {avg_pct_change:+.2f}%")
    print(f"Variação máxima:      {max_pct_change:.2f}%")
    print()
    
    print("INTERPRETAÇÃO:")
    if max_pct_change < 1.0:
        print("  Status: VALIDADO")
        print("  Análise: Mudança não introduziu regressão de performance")
        print("  Razão: Variação < 1% (dentro do ruído estatístico)")
        print("  Ação: Nenhuma")
    elif max_pct_change < 5.0:
        print("  Status: ACEITÁVEL")
        print("  Análise: Variação detectada mas dentro de limites toleráveis")
        print("  Razão: Variação < 5% (aceitável para mudanças de algoritmo)")
        print("  Ação: Monitorar em produção")
    elif max_pct_change < 10.0:
        print("  Status: ATENÇÃO")
        print("  Análise: Variação moderada detectada")
        print("  Razão: 5% < Variação < 10% (requer análise)")
        print("  Ação: Investigar causa específica")
    else:
        print("  Status: REGRESSÃO SIGNIFICATIVA")
        print("  Análise: Mudança introduziu impacto substancial")
        print("  Razão: Variação > 10% (impacto notável)")
        print("  Ação: Avaliar tradeoff custo/benefício da mudança")
    
    print()
    print("CONTEXTO DA COMPARAÇÃO:")
    print("  Esta análise compara dois experimentos user-profile completos.")
    print("  Cada experimento simula cargas de trabalho realistas (DM, Small, Medium, Large)")
    print("  com diferentes políticas de rotação (Paranoid, PQ3, Balanced, Relaxed).")
    print()
    print("  Regressões em [SETUP] afetam apenas a criação inicial de salas (raro).")
    print("  Regressões em [ROTAÇÃO] afetam redistribuição de chaves (esporádico).")
    print("  Regressões em [STEADY-STATE] afetam todas as mensagens (crítico).")
    print()
    print("=" * 80)

if __name__ == '__main__':
    main()
