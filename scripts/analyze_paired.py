#!/usr/bin/env python3
"""
Analise Pareada de Benchmarks Classical vs Hybrid

Analisa experimentos pareados com metodologia estatistica robusta:
- Dados: CSV em formato long/tidy com batch_id, pair_id, repeat_id
- Estatisticas robustas: mediana, IQR, P95, bootstrap CI
- Testes adaptativos: Shapiro-Wilk -> paired t-test ou Wilcoxon
- Effect sizes: Cohen's d (parametrico) ou Cliff's delta (nao-parametrico)
- Correcao de multiplas comparacoes: Holm-Bonferroni
- Analise por fase: Agreement, Initial Distribution, Rotation

Metricas analisadas:
1. Bandwidth total por fase (Classical vs Hybrid)
2. Overhead PQC por fase (componentes Classical vs PQC)
3. Mensagens: numero de rotacoes e forcamentos
4. Tempo por fase (Setup, Rotation)
5. Correlacao: Bandwidth vs Tempo - trade-off seguranca/desempenho

===============================================================================
DESIGN DO EXPERIMENTO
===============================================================================

Paired Design:
- Cada repeat_id tem 2 runs: Classical e Hybrid
- Controla variancia de hardware/ambiente
- Permite teste pareado (maior poder estatistico)

Metricas coletadas (por fase):
- Agreement: Acordo de chaves PQXDH (X3DH + Kyber KEM)
- Initial Distribution: Distribuicao inicial de sessao Megolm
- Rotation: Rotacoes de sessao Megolm (N mensagens)
- Setup Time: Tempo total (Agreement + Initial Distribution)
- Rotation Time: Tempo de rotacoes

Componentes de Bandwidth Classical:
- Agreement: 96B (Curve25519 ECDH)
- Setup: 664B (PreKeyMessage Olm)
- Rotation: N × 664B (MegolmKeys)

Componentes de Bandwidth Hybrid:
- Agreement: 896B (Curve25519 + Kyber768 KEM)
- Setup: 2856B (PreKeyMessage + Ratchet Key + KEM)
- Rotation: N × 2856B (MegolmKeys com PQC)

Estrutura detalhada Bandwidth Hybrid:
- Payload Classical: 498B (PreKeyMessage Olm)
- Ratchet Key: 1219B (32B X25519 + 1184B Kyber768 + 3B metadata)
- KEM Ciphertext: 1088B (apenas em forcamentos/mudanca de direcao)

===============================================================================
TESTES ESTATISTICOS
===============================================================================

1. Normalidade: Shapiro-Wilk (5 <= n <= 5000)
2. Teste Pareado:
   - Normal: Paired t-test + Cohen's d
   - Nao-normal: Wilcoxon signed-rank + Cliff's delta
3. Correcao: Holm-Bonferroni (multiplas metricas)
4. IC: 95% t-Student (normal) ou Bootstrap (nao-normal)

Hipoteses por fase (Bandwidth):
- Agreement: H0: overhead <= 0% | H1: overhead > 0%
  * Esperado: 9.33x (Kyber768 KEM dominante)
- Setup: H0: overhead <= 0% | H1: overhead > 0%
  * Esperado: 4.30x (Ratchet Key + KEM)
- Rotation: H0: overhead <= 0% | H1: overhead > 0%
  * Esperado: 4.30x (Ratchet Key sem KEM na maioria)

Hipoteses por fase (Tempo):
- Setup: H0: overhead <= 0% | H1: overhead > 0%
  * Esperado: 1.4x (Kyber KeyGen rapido)
- Rotation: H0: overhead <= 0% | H1: overhead > 0%
  * Esperado: 1.6x (operacoes PQC mais lentas)

===============================================================================
"""

import pandas as pd
import numpy as np
from scipy import stats
from pathlib import Path
import sys
import warnings
from datetime import datetime

warnings.filterwarnings('ignore', category=RuntimeWarning)


def shapiro_test(data, alpha=0.05):
    """
    Testa normalidade com Shapiro-Wilk.
    
    Returns:
        tuple: (is_normal, p_value, interpretation)
    """
    if len(data) < 3:
        return False, np.nan, "n < 3 (insuficiente)"
    
    if len(data) > 5000:
        return False, np.nan, "n > 5000 (usa Wilcoxon)"
    
    stat, p = stats.shapiro(data)
    is_normal = p > alpha
    interpretation = "Normal" if is_normal else "Nao-normal"
    
    return is_normal, p, interpretation


def cohens_d(group1, group2):
    """
    Calcula Cohen's d (effect size parametrico).
    
    Interpretacao:
        |d| < 0.2: trivial
        |d| < 0.5: small
        |d| < 0.8: medium
        |d| >= 0.8: large
    """
    n1, n2 = len(group1), len(group2)
    var1, var2 = np.var(group1, ddof=1), np.var(group2, ddof=1)
    pooled_std = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))
    
    if pooled_std == 0:
        return 0.0
    
    return (np.mean(group1) - np.mean(group2)) / pooled_std


def cliffs_delta(group1, group2):
    """
    Calcula Cliff's delta (effect size nao-parametrico).
    
    Interpretacao:
        |delta| < 0.147: negligible
        |delta| < 0.330: small
        |delta| < 0.474: medium
        |delta| >= 0.474: large
    """
    n1, n2 = len(group1), len(group2)
    dominance = sum(sum(1 for b in group2 if a > b) - 
                   sum(1 for b in group2 if a < b) for a in group1)
    return dominance / (n1 * n2) if (n1 * n2) > 0 else 0.0


def bootstrap_ci_median(data, confidence=0.95, n_bootstrap=10000):
    """
    Calcula IC bootstrap para mediana.
    """
    if len(data) < 2:
        return np.nan, np.nan
    
    rng = np.random.RandomState(42)
    bootstrap_medians = []
    
    for _ in range(n_bootstrap):
        sample = rng.choice(data, size=len(data), replace=True)
        bootstrap_medians.append(np.median(sample))
    
    alpha = 1 - confidence
    lower = np.percentile(bootstrap_medians, 100 * alpha / 2)
    upper = np.percentile(bootstrap_medians, 100 * (1 - alpha / 2))
    
    return lower, upper


def holm_bonferroni_correction(p_values):
    """
    Aplica correcao Holm-Bonferroni para multiplas comparacoes.
    
    Menos conservadora que Bonferroni simples, controla FWER (Family-Wise Error Rate)
    
    IMPORTANTE: Garante monotonicidade dos p-values ajustados para evitar
    inconsistencias logicas (p1 < p2 mas p_adj1 > p_adj2)
    
    Referencia: Holm (1979), "A Simple Sequentially Rejective Multiple Test Procedure"
    
    Returns:
        list: p-values ajustados
    """
    p_values = np.asarray(p_values, dtype=float)
    n = len(p_values)
    
    # Ordenar p-values
    sorted_indices = np.argsort(p_values)
    adjusted = np.zeros(n)
    
    # Aplicar correcao de Holm
    for rank, idx in enumerate(sorted_indices):
        adjusted[idx] = min(1.0, p_values[idx] * (n - rank))
    
    # Garantir monotonicidade: p_adj[i] <= p_adj[i+1] na ordem original
    # Isso previne inconsistencias logicas onde p_raw[i] < p_raw[j] mas p_adj[i] > p_adj[j]
    for i in range(1, n):
        prev_idx = sorted_indices[i-1]
        curr_idx = sorted_indices[i]
        adjusted[curr_idx] = max(adjusted[curr_idx], adjusted[prev_idx])
    
    return adjusted


def paired_test_analysis(classical, hybrid, metric_name, alpha=0.05):
    """
    Realiza analise pareada completa: normalidade, teste, effect size, IC.
    
    Returns:
        dict: resultados da analise
    """
    delta = hybrid - classical
    n = len(delta)
    
    # Remover NaN
    valid_mask = ~(np.isnan(classical) | np.isnan(hybrid))
    classical_clean = classical[valid_mask]
    hybrid_clean = hybrid[valid_mask]
    delta_clean = delta[valid_mask]
    n_valid = len(delta_clean)
    
    if n_valid < 3:
        return {
            'metric': metric_name,
            'n': n_valid,
            'status': 'Insuficiente (n < 3)',
            'test': 'N/A',
            'p_value': np.nan,
            'p_adjusted': np.nan,
            'significant': False,
            'effect_size': np.nan,
            'effect_interpretation': 'N/A'
        }
    
    # Normalidade
    is_normal, p_shapiro, norm_interp = shapiro_test(delta_clean, alpha)
    
    # Estatisticas descritivas
    classical_median = np.median(classical_clean)
    hybrid_median = np.median(hybrid_clean)
    classical_mean = np.mean(classical_clean)
    hybrid_mean = np.mean(hybrid_clean)
    
    # Overhead baseado em mediana (mais robusto)
    overhead_pct = ((hybrid_median - classical_median) / classical_median * 100) if classical_median > 0 else 0.0
    
    # Teste pareado
    if is_normal:
        # Paired t-test
        t_stat, p_value = stats.ttest_rel(hybrid_clean, classical_clean, alternative='two-sided')
        test_name = 'Paired t-test'
        
        # Cohen's d
        effect = cohens_d(hybrid_clean, classical_clean)
        if abs(effect) < 0.2:
            effect_interp = 'trivial'
        elif abs(effect) < 0.5:
            effect_interp = 'small'
        elif abs(effect) < 0.8:
            effect_interp = 'medium'
        else:
            effect_interp = 'large'
        
        # IC t-Student
        sem = stats.sem(delta_clean)
        ci_lower, ci_upper = stats.t.interval(0.95, n_valid - 1, loc=np.mean(delta_clean), scale=sem)
        
    else:
        # Wilcoxon signed-rank
        stat, p_value = stats.wilcoxon(delta_clean, alternative='two-sided')
        test_name = 'Wilcoxon signed-rank'
        
        # Cliff's delta
        effect = cliffs_delta(hybrid_clean, classical_clean)
        if abs(effect) < 0.147:
            effect_interp = 'negligible'
        elif abs(effect) < 0.330:
            effect_interp = 'small'
        elif abs(effect) < 0.474:
            effect_interp = 'medium'
        else:
            effect_interp = 'large'
        
        # IC bootstrap
        ci_lower, ci_upper = bootstrap_ci_median(delta_clean, confidence=0.95)
    
    # IQR e percentis
    q1, q3 = np.percentile(delta_clean, [25, 75])
    iqr = q3 - q1
    p95 = np.percentile(delta_clean, 95)
    
    return {
        'metric': metric_name,
        'n': n_valid,
        'classical_median': classical_median,
        'hybrid_median': hybrid_median,
        'classical_mean': classical_mean,
        'hybrid_mean': hybrid_mean,
        'delta_median': np.median(delta_clean),
        'delta_mean': np.mean(delta_clean),
        'delta_iqr': iqr,
        'delta_p95': p95,
        'overhead_pct': overhead_pct,
        'is_normal': is_normal,
        'p_shapiro': p_shapiro,
        'test': test_name,
        'p_value': p_value,
        'p_adjusted': np.nan,  # Sera preenchido depois
        'significant': False,  # Sera atualizado depois
        'effect_size': effect,
        'effect_interpretation': effect_interp,
        'ci_lower': ci_lower,
        'ci_upper': ci_upper
    }


def paired_analysis_by_room_type(df, metric, metric_name):
    """
    Analise pareada agrupada por tipo de sala (como analyze_user_profile_paired.py).
    
    Args:
        df: DataFrame com dados pareados
        metric: Coluna a analisar
        metric_name: Nome da metrica para exibicao
    
    Returns:
        DataFrame com resultados da analise
    """
    results = []
    
    if 'room_type' not in df.columns:
        print(f"AVISO: Coluna 'room_type' nao encontrada")
        return pd.DataFrame()
    
    room_types = df['room_type'].unique()
    
    for room_type in sorted(room_types):
        df_room = df[df['room_type'] == room_type].copy()
        
        # Separar Classical (repeat_id=0) e Hybrid (repeat_id=1)
        classical = df_room[df_room['repeat_id'] == 0][metric].values
        hybrid = df_room[df_room['repeat_id'] == 1][metric].values
        
        # Verificar se temos dados pareados
        n_pairs = min(len(classical), len(hybrid))
        if n_pairs == 0:
            continue
        
        # Truncar para mesmo tamanho (se necessario)
        classical = classical[:n_pairs]
        hybrid = hybrid[:n_pairs]
        
        # Diferencas pareadas
        diffs = hybrid - classical
        
        # Remover outliers (metodo IQR) - APENAS para tempo, NAO para bandwidth
        # Bandwidth eh deterministica (tamanho fixo de chaves PQC)
        if 'bandwidth' in metric or 'bytes' in metric:
            # NAO remover outliers de bandwidth
            diffs_clean = diffs
            classical_clean = classical
            hybrid_clean = hybrid
            n_outliers = 0
        else:
            # Remover outliers de metricas de tempo
            outlier_mask = detect_outliers_iqr(diffs)
            diffs_clean = diffs[~outlier_mask]
            classical_clean = classical[~outlier_mask]
            hybrid_clean = hybrid[~outlier_mask]
            n_outliers = np.sum(outlier_mask)
        
        n_clean = len(diffs_clean)
        
        if n_clean < 3:
            print(f"  {room_type}: Poucos dados apos remocao de outliers (n={n_clean})")
            continue
        
        # Estatisticas robustas
        delta_median = np.median(diffs_clean)
        delta_iqr = np.percentile(diffs_clean, 75) - np.percentile(diffs_clean, 25)
        delta_p95 = np.percentile(diffs_clean, 95)
        delta_p99 = np.percentile(diffs_clean, 99)
        
        # Bootstrap CI para mediana
        ci_lower, ci_upper = bootstrap_ci_median(diffs_clean)
        
        # Overhead percentual
        classical_median = np.median(classical_clean)
        overhead_pct = (delta_median / classical_median * 100) if classical_median > 0 else 0
        
        # Teste de normalidade
        _, p_shapiro = stats.shapiro(diffs_clean) if len(diffs_clean) >= 3 else (None, 0)
        is_normal = p_shapiro > 0.05 if p_shapiro is not None else False
        
        # Teste estatistico adaptativo
        if is_normal and n_clean >= 5:
            # Paired t-test (parametrico)
            statistic, p_value = stats.ttest_rel(hybrid_clean, classical_clean)
            test_name = "paired_t"
            delta_mean = np.mean(diffs_clean)
            delta_std = np.std(diffs_clean, ddof=1)
            effect_size = cohens_d(classical_clean, hybrid_clean)
            effect_label = "Cohen's d"
        else:
            # Wilcoxon (nao-parametrico)
            statistic, p_value = stats.wilcoxon(hybrid_clean, classical_clean, alternative='two-sided')
            test_name = "Wilcoxon"
            delta_mean = None
            delta_std = None
            effect_size = cliffs_delta(classical_clean, hybrid_clean)
            effect_label = "Cliff's delta"
        
        results.append({
            'room_type': room_type,
            'metric': metric_name,
            'n_pairs': n_pairs,
            'n_clean': n_clean,
            'n_outliers': n_outliers,
            'classical_median': classical_median,
            'hybrid_median': np.median(hybrid_clean),
            'delta_median': delta_median,
            'delta_iqr': delta_iqr,
            'delta_p95': delta_p95,
            'delta_p99': delta_p99,
            'ci_lower': ci_lower,
            'ci_upper': ci_upper,
            'overhead_pct': overhead_pct,
            'delta_mean': delta_mean,
            'delta_std': delta_std,
            'p_shapiro': p_shapiro,
            'is_normal': is_normal,
            'test_name': test_name,
            'p_value': p_value,
            'effect_size': effect_size,
            'effect_label': effect_label,
        })
    
    return pd.DataFrame(results)


def detect_outliers_iqr(data, threshold=1.5):
    """
    Detecta outliers usando metodo IQR.
    
    Args:
        data: Array de dados
        threshold: Multiplicador do IQR (default=1.5)
    
    Returns:
        Boolean mask indicando outliers
    """
    q1 = np.percentile(data, 25)
    q3 = np.percentile(data, 75)
    iqr = q3 - q1
    
    lower_bound = q1 - threshold * iqr
    upper_bound = q3 + threshold * iqr
    
    return (data < lower_bound) | (data > upper_bound)


def analyze_bandwidth_by_phase(df):
    """
    Analisa largura de banda por fase (Agreement, Initial Distribution, Rotation).
    
    Para cada fase e tipo de sala:
    - Calcula estatisticas robustas (mediana, IQR, P95)
    - Executa testes pareados (t-test ou Wilcoxon)
    - Computa effect sizes e intervalos de confianca
    - Aplica correcao Holm-Bonferroni
    
    Returns:
        dict: resultados por fase (Agreement, Initial_Distribution, Rotation)
    """
    print("\n" + "="*80)
    print("ANALISE DE LARGURA DE BANDA POR FASE")
    print("="*80)
    
    # Verificar estrutura do CSV
    required_cols = ['batch_id', 'pair_id', 'repeat_id', 'crypto_mode', 'room_type']
    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        print(f"\nERRO: Colunas ausentes: {missing}")
        return {}
    
    print(f"\nEstrutura do CSV:")
    print(f"  Total de linhas: {len(df)}")
    print(f"  Distribuicao:")
    print(df.groupby(['room_type', 'crypto_mode']).size())
    
    # Fases a analisar
    phases = {
        'Agreement': 'bandwidth_agreement',
        'Initial_Distribution': 'bandwidth_initial_distribution',
        'Rotation': 'bandwidth_rotation'
    }
    
    results = {}
    all_p_values = []
    test_names = []
    
    for phase_name, col_name in phases.items():
        print(f"\n{'-'*80}")
        print(f"FASE: {phase_name}")
        print(f"{'-'*80}")
        
        if col_name not in df.columns:
            print(f"AVISO: Coluna '{col_name}' nao encontrada no CSV")
            continue
        
        # Analise pareada por room_type
        results_df = paired_analysis_by_room_type(df, col_name, phase_name)
        
        if len(results_df) == 0:
            print(f"AVISO: Nenhum resultado para {phase_name}")
            continue
        
        # Imprimir resultados da fase
        for _, row in results_df.iterrows():
            print(f"\n{row['room_type']} ({row['n_clean']} pares):")
            print(f"  Classical: {row['classical_median']:.0f}B")
            print(f"  Hybrid:    {row['hybrid_median']:.0f}B")
            print(f"  Overhead:  {row['overhead_pct']:+.2f}%")
            print(f"  Teste:     {row['test_name']} (p={row['p_value']:.4e})")
            print(f"  Effect:    {row['effect_size']:.3f} ({row['effect_label']})")
        
        # Armazenar p-values para correcao
        all_p_values.extend(results_df['p_value'].values)
        test_names.extend([f"{phase_name}_{rt}" for rt in results_df['room_type'].values])
        
        results[phase_name] = results_df
    
    # Correcao Holm-Bonferroni
    if all_p_values:
        p_adjusted = holm_bonferroni_correction(all_p_values)
        
        print(f"\n{'-'*80}")
        print("CORRECAO HOLM-BONFERRONI")
        print(f"{'-'*80}")
        
        for i, test_name in enumerate(test_names):
            sig_marker = "***" if p_adjusted[i] < 0.05 else "n.s."
            print(f"{test_name:30s} | p_raw: {all_p_values[i]:.4e} | p_adj: {p_adjusted[i]:.4e} | {sig_marker}")
        
        # Atualizar DataFrames com p_adjusted
        idx = 0
        for phase_name, df_phase in results.items():
            n_tests = len(df_phase)
            df_phase['p_adjusted'] = p_adjusted[idx:idx+n_tests]
            df_phase['significant'] = df_phase['p_adjusted'] < 0.05
            idx += n_tests
    
    return results


def analyze_pqc_components(df):
    """
    Analisa decomposicao de bandwidth em componentes Classical e PQC.
    
    Calcula proporcao Classical vs PQC em cada fase:
    - Agreement: 96B Classical vs 800B PQC (Kyber768 KEM)
    - Setup: 498B Classical vs 2307B PQC (Ratchet Key + KEM)
    - Rotation: 498B Classical vs ~1219B PQC (Ratchet Key, KEM opcional)
    
    Components:
    - Agreement: Classical 96B vs Hybrid 896B (8B + 800B KEM)
    - Setup: Classical 664B vs Hybrid 2856B (498B + 1219B ratchet + 1088B KEM)
    - Rotation: Classical 664B vs Hybrid 2856B (maioria sem KEM)
    
    Returns:
        dict: proporcoes Classical/PQC por fase
    """
    print("\n" + "="*80)
    print("ANALISE DE COMPONENTES PQC")
    print("="*80)
    
    # Verificar se temos colunas detalhadas
    cols_classical = [
        'bandwidth_agreement_classical',
        'bandwidth_initial_distribution_classical',
        'bandwidth_rotation_classical'
    ]
    
    cols_pqc = [
        'bandwidth_agreement_pqc',
        'bandwidth_initial_distribution_pqc',
        'bandwidth_rotation_pqc'
    ]
    
    has_breakdown = all(col in df.columns for col in cols_classical + cols_pqc)
    
    if not has_breakdown:
        print("\nAVISO: CSV nao contem colunas detalhadas de componentes Classical/PQC")
        return {}
    
    # AGREGACAO: Somar por (batch_id, pair_id, repeat_id, crypto_mode)
    print(f"\nAgregando componentes por run...")
    df_agg = df.groupby(['batch_id', 'pair_id', 'repeat_id', 'crypto_mode'], as_index=False)[
        cols_classical + cols_pqc
    ].sum()
    
    # Filtrar apenas runs Hybrid
    df_hybrid = df_agg[df_agg['crypto_mode'] == 'Hybrid'].copy()
    
    if len(df_hybrid) == 0:
        print("\nAVISO: Nenhum run Hybrid encontrado")
        return {}
    
    print(f"N runs Hybrid agregados: {len(df_hybrid)}")
    
    # Analise por fase
    phases = {
        'Agreement': ('bandwidth_agreement_classical', 'bandwidth_agreement_pqc'),
        'Setup': ('bandwidth_initial_distribution_classical', 'bandwidth_initial_distribution_pqc'),
        'Rotation': ('bandwidth_rotation_classical', 'bandwidth_rotation_pqc')
    }
    
    results = {}
    
    for phase_name, (col_classical, col_pqc) in phases.items():
        print(f"\n{'-'*80}")
        print(f"Fase: {phase_name}")
        print(f"{'-'*80}")
        
        classical_bytes = df_hybrid[col_classical].dropna()
        pqc_bytes = df_hybrid[col_pqc].dropna()
        
        if len(classical_bytes) == 0 or len(pqc_bytes) == 0:
            print(f"AVISO: Dados ausentes para {phase_name}")
            continue
        
        classical_median = np.median(classical_bytes)
        pqc_median = np.median(pqc_bytes)
        total_median = classical_median + pqc_median
        
        classical_pct = (classical_median / total_median * 100) if total_median > 0 else 0
        pqc_pct = (pqc_median / total_median * 100) if total_median > 0 else 0
        
        print(f"\nComponente Classical: {classical_median:.0f}B ({classical_pct:.1f}%)")
        print(f"Componente PQC:       {pqc_median:.0f}B ({pqc_pct:.1f}%)")
        print(f"Total:                {total_median:.0f}B")
        
        # Estrutura esperada
        if phase_name == 'Agreement':
            print(f"\nEstrutura esperada (Agreement):")
            print(f"  Classical: 96B (Curve25519 ECDH)")
            print(f"  PQC: 800B (Kyber768 KEM ciphertext)")
            print(f"  Total: 896B")
            
        elif phase_name == 'Setup':
            print(f"\nEstrutura esperada (Setup):")
            print(f"  Classical Payload: 498B (PreKeyMessage Olm)")
            print(f"  Ratchet Key: 1219B (32B X25519 + 1184B Kyber768 + 3B metadata)")
            print(f"  KEM Ciphertext: 1088B (forcamento inicial)")
            print(f"  Total: 2805B (+ 51B base64/JSON)")
            
        elif phase_name == 'Rotation':
            print(f"\nEstrutura esperada (Rotation):")
            print(f"  Classical Payload: 498B (MegolmKey Olm)")
            print(f"  Ratchet Key: 1219B (sempre presente)")
            print(f"  KEM Ciphertext: 0-1088B (apenas forcamentos/mudanca direcao)")
            print(f"  Mediana Total: ~1768B (sem KEM) ou ~2856B (com KEM)")
        
        results[phase_name] = {
            'classical_median': classical_median,
            'pqc_median': pqc_median,
            'total_median': total_median,
            'classical_pct': classical_pct,
            'pqc_pct': pqc_pct
        }
    
    return results


def analyze_rotation_metrics(df):
    """
    Analisa metricas operacionais de rotacao de chaves Megolm.
    
    Compara Classical vs Hybrid:
    - Numero de mensagens de rotacao (esperado: 1.0x - mesma quantidade)
    - Numero de forcamentos asimetricos (ratchet advances)
    - Impacto de forcamentos na largura de banda (KEM adicional: +1088B)
    
    Valida que contador de mensagens e consistente entre Classical/Hybrid.
    
    Returns:
        dict: mediana de mensagens, ratio Hybrid/Classical
    """
    print("\n" + "="*80)
    print("ANALISE DE METRICAS DE ROTACAO")
    print("="*80)
    
    # Verificar colunas
    if 'num_rotation_messages' not in df.columns:
        print("\nAVISO: Coluna 'num_rotation_messages' nao encontrada")
        return {}
    
    # AGREGACAO: Somar por (batch_id, pair_id, repeat_id, crypto_mode)
    agg_cols = ['num_rotation_messages', 'bandwidth_rotation']
    if 'num_asymmetric_advances' in df.columns:
        agg_cols.append('num_asymmetric_advances')
    
    agg_cols_valid = [col for col in agg_cols if col in df.columns]
    
    print(f"\nAgregando metricas de rotacao por run...")
    df_agg = df.groupby(['batch_id', 'pair_id', 'repeat_id', 'crypto_mode'], as_index=False)[
        agg_cols_valid
    ].sum()
    
    # Comparar Classical vs Hybrid
    df_classical = df_agg[df_agg['crypto_mode'] == 'Classical']
    df_hybrid = df_agg[df_agg['crypto_mode'] == 'Hybrid']
    
    if len(df_classical) == 0 or len(df_hybrid) == 0:
        print("\nAVISO: Dados Classical ou Hybrid ausentes")
        return {}
    
    # Numero de mensagens
    classical_msgs = df_classical['num_rotation_messages'].dropna()
    hybrid_msgs = df_hybrid['num_rotation_messages'].dropna()
    
    print(f"\nNumero de Mensagens de Rotacao:")
    print(f"Classical - Mediana: {np.median(classical_msgs):.0f} | Media: {np.mean(classical_msgs):.1f}")
    print(f"Hybrid    - Mediana: {np.median(hybrid_msgs):.0f} | Media: {np.mean(hybrid_msgs):.1f}")
    
    # Ratio
    ratio = np.median(hybrid_msgs) / np.median(classical_msgs) if np.median(classical_msgs) > 0 else 0
    print(f"Ratio Hybrid/Classical: {ratio:.2f}x")
    
    if abs(ratio - 1.0) > 0.05:
        print(f"AVISO: Ratio diferente de 1.0x (esperado igualdade)")
    else:
        print(f"OK: Ratio proximo de 1.0x (contador real)")
    
    # Forcamentos asimetricos (se disponivel)
    if 'num_asymmetric_advances' in df.columns:
        classical_forces = df_classical['num_asymmetric_advances'].dropna()
        hybrid_forces = df_hybrid['num_asymmetric_advances'].dropna()
        
        print(f"\nForcamentos Asimetricos:")
        print(f"Classical - Mediana: {np.median(classical_forces):.0f} | Media: {np.mean(classical_forces):.1f}")
        print(f"Hybrid    - Mediana: {np.median(hybrid_forces):.0f} | Media: {np.mean(hybrid_forces):.1f}")
        
        # Impacto do forcamento na largura de banda
        if 'bandwidth_rotation' in df.columns and len(hybrid_msgs) > 0:
            hybrid_bw = df_hybrid['bandwidth_rotation'].dropna()
            
            if len(hybrid_bw) == len(hybrid_msgs) and len(hybrid_bw) == len(hybrid_forces):
                hybrid_bytes_per_msg = hybrid_bw / hybrid_msgs
                
                print(f"\nImpacto de Forcamentos no Hybrid:")
                print(f"Bytes/mensagem - Mediana: {np.median(hybrid_bytes_per_msg):.0f}B")
                print(f"Estrutura esperada:")
                print(f"  Sem KEM: ~1768B (498B + 1219B + 51B overhead)")
                print(f"  Com KEM: ~2856B (498B + 1219B + 1088B + 51B overhead)")
                
                median_bpm = np.median(hybrid_bytes_per_msg)
                if median_bpm < 2000:
                    print(f"  -> Indica baixa taxa de forcamentos (maioria sem KEM)")
                else:
                    print(f"  -> Indica alta taxa de forcamentos (maioria com KEM)")
    
    return {
        'classical_msgs_median': np.median(classical_msgs),
        'hybrid_msgs_median': np.median(hybrid_msgs),
        'ratio': ratio
    }


def analyze_time_by_phase(df):
    """
    Analisa metricas de TEMPO por fase (Setup, Rotation).
    
    Metodologia identica a analyze_bandwidth_by_phase:
    - Setup time: Agreement + Initial Distribution (tempo total de configuracao)
    - Rotation time: Tempo de rotacoes de chaves Megolm
    
    Remove outliers de tempo (metodo IQR) antes da analise.
    Bandwidth NAO tem outliers removidos (deterministico).
    
    IMPORTANTE: Setup time = Agreement + Initial Distribution
    
    Returns:
        dict: resultados por fase (Setup, Rotation)
    """
    print("\n" + "="*80)
    print("ANALISE DE TEMPO POR FASE")
    print("="*80)
    
    # Verificar estrutura do CSV
    required_cols = ['batch_id', 'pair_id', 'repeat_id', 'crypto_mode', 'room_type']
    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        print(f"\nERRO: Colunas ausentes: {missing}")
        return {}
    
    # Verificar metricas de tempo
    time_cols = ['setup_time_ms', 'rotation_time_ms']
    missing_time = [col for col in time_cols if col not in df.columns]
    if missing_time:
        print(f"\nERRO: Metricas de tempo ausentes: {missing_time}")
        return {}
    
    print(f"\nEstrutura do CSV:")
    print(f"  Total de linhas: {len(df)}")
    print(f"  Distribuicao:")
    print(df.groupby(['room_type', 'crypto_mode']).size())
    
    # Fases a analisar
    # NOTA: setup_time_ms inclui Agreement + Initial Distribution
    phases = {
        'Setup': 'setup_time_ms',           # Agreement + Initial Distribution
        'Rotation': 'rotation_time_ms'      # Rotation apenas
    }
    
    results = {}
    all_p_values = []
    test_names = []
    
    for phase_name, col_name in phases.items():
        print(f"\n{'-'*80}")
        print(f"FASE: {phase_name}")
        print(f"{'-'*80}")
        
        if col_name not in df.columns:
            print(f"AVISO: Coluna '{col_name}' nao encontrada no CSV")
            continue
        
        # Analise pareada por room_type
        results_df = paired_analysis_by_room_type(df, col_name, phase_name)
        
        if len(results_df) == 0:
            print(f"AVISO: Nenhum resultado para {phase_name}")
            continue
        
        # Imprimir resultados da fase
        for _, row in results_df.iterrows():
            print(f"\n{row['room_type']} ({row['n_clean']} pares):")
            print(f"  Classical: {row['classical_median']:.2f}ms")
            print(f"  Hybrid:    {row['hybrid_median']:.2f}ms")
            print(f"  Overhead:  {row['overhead_pct']:+.2f}%")
            print(f"  Teste:     {row['test_name']} (p={row['p_value']:.4e})")
            print(f"  Effect:    {row['effect_size']:.3f} ({row['effect_label']})")
        
        # Armazenar p-values para correcao
        all_p_values.extend(results_df['p_value'].values)
        test_names.extend([f"{phase_name}_{rt}" for rt in results_df['room_type'].values])
        
        results[phase_name] = results_df
    
    # Correcao Holm-Bonferroni
    if all_p_values:
        p_adjusted = holm_bonferroni_correction(all_p_values)
        
        print(f"\n{'-'*80}")
        print("CORRECAO HOLM-BONFERRONI (TEMPO)")
        print(f"{'-'*80}")
        
        for i, test_name in enumerate(test_names):
            sig_marker = "***" if p_adjusted[i] < 0.05 else "n.s."
            print(f"{test_name:30s} | p_raw: {all_p_values[i]:.4e} | p_adj: {p_adjusted[i]:.4e} | {sig_marker}")
        
        # Atualizar DataFrames com p_adjusted
        idx = 0
        for phase_name, df_phase in results.items():
            n_tests = len(df_phase)
            df_phase['p_adjusted'] = p_adjusted[idx:idx+n_tests]
            df_phase['significant'] = df_phase['p_adjusted'] < 0.05
            idx += n_tests
    
    return results


def analyze_bandwidth_time_correlation(df, results_bandwidth, results_time):
    """
    Analisa correlacao entre overhead de bandwidth e overhead de tempo.
    
    Calcula ratio: (Bandwidth overhead) / (Tempo overhead) por fase.
    
    Interpretacao do ratio:
    - Ratio alto (>5): Operacoes rapidas geram payloads grandes
      Exemplo: Kyber KeyGen rapido (~1.3ms) mas gera 2.6KB
    - Ratio medio (2-5): Equilibrio entre bandwidth e tempo
    - Ratio baixo (<2): Overheads proporcionais
    
    Hipotese: Maior bandwidth -> maior overhead de tempo?
    - Agreement: Alto bandwidth (24x), tempo moderado (1.4x)?
    - Setup: Medio bandwidth (6.5x), tempo moderado (1.4x)?
    - Rotation: Medio bandwidth (3.5x), tempo moderado (1.6x)?
    
    Returns:
        dict: overhead bandwidth/tempo e ratio por fase
    """
    print("\n" + "="*80)
    print("ANALISE DE CORRELACAO: BANDWIDTH vs TEMPO")
    print("="*80)
    
    if not results_bandwidth or not results_time:
        print("\nAVISO: Resultados insuficientes para analise de correlacao")
        return {}
    
    print("\nOverhead comparativo (Mediana Agregada):")
    print("-" * 60)
    print(f"{'Fase':<20s} {'Bandwidth':>12s} {'Tempo':>12s} {'Ratio':>10s}")
    print("-" * 60)
    
    correlations = {}
    
    # Agreement/Setup: bandwidth tem 2 fases, tempo tem 1 (setup = agreement + init dist)
    if 'Agreement' in results_bandwidth and 'Initial_Distribution' in results_bandwidth and 'Setup' in results_time:
        # Bandwidth total do setup
        bw_agreement = results_bandwidth['Agreement']
        bw_init_dist = results_bandwidth['Initial_Distribution']
        
        if isinstance(bw_agreement, pd.DataFrame) and isinstance(bw_init_dist, pd.DataFrame):
            bw_setup_agg = (bw_agreement['hybrid_median'].sum() + bw_init_dist['hybrid_median'].sum()) / \
                          (bw_agreement['classical_median'].sum() + bw_init_dist['classical_median'].sum())
            
            # Tempo do setup
            time_setup = results_time['Setup']
            if isinstance(time_setup, pd.DataFrame) and len(time_setup) > 0:
                time_setup_agg = time_setup['hybrid_median'].sum() / time_setup['classical_median'].sum()
                
                ratio = bw_setup_agg / time_setup_agg if time_setup_agg > 0 else 0
                
                print(f"{'Setup (Agr+Init)':<20s} {bw_setup_agg:>11.2f}x {time_setup_agg:>11.2f}x {ratio:>9.2f}x")
                
                correlations['Setup'] = {
                    'bandwidth_overhead': bw_setup_agg,
                    'time_overhead': time_setup_agg,
                    'ratio': ratio
                }
    
    # Rotation
    if 'Rotation' in results_bandwidth and 'Rotation' in results_time:
        bw_rotation = results_bandwidth['Rotation']
        time_rotation = results_time['Rotation']
        
        if isinstance(bw_rotation, pd.DataFrame) and isinstance(time_rotation, pd.DataFrame):
            if len(bw_rotation) > 0 and len(time_rotation) > 0:
                bw_rot_agg = bw_rotation['hybrid_median'].sum() / bw_rotation['classical_median'].sum()
                time_rot_agg = time_rotation['hybrid_median'].sum() / time_rotation['classical_median'].sum()
                
                ratio = bw_rot_agg / time_rot_agg if time_rot_agg > 0 else 0
                
                print(f"{'Rotation':<20s} {bw_rot_agg:>11.2f}x {time_rot_agg:>11.2f}x {ratio:>9.2f}x")
                
                correlations['Rotation'] = {
                    'bandwidth_overhead': bw_rot_agg,
                    'time_overhead': time_rot_agg,
                    'ratio': ratio
                }
    
    print("-" * 60)
    print("\nInterpretacao:")
    print("  Ratio > 1.0: Bandwidth overhead > Tempo overhead")
    print("  Ratio < 1.0: Tempo overhead > Bandwidth overhead")
    print("  Ratio ~ 1.0: Overheads proporcionais")
    
    print("\nInsight esperado:")
    print("  Setup: Alto ratio (24x/1.4x ~ 17) - Kyber KeyGen rapido, mas gera chave grande")
    print("  Rotation: Medio ratio (3.5x/1.6x ~ 2.2) - Operacoes PQC mais lentas, payload menor")
    
    return correlations


def generate_summary(results_bandwidth, results_components, results_rotation, results_time=None, correlations=None):
    """
    Gera resumo executivo consolidado da analise pareada.
    
    Secoes do resumo:
    1. Overhead de bandwidth por fase (Agreement, Setup, Rotation)
    2. Significancia estatistica (Holm-Bonferroni)
    3. Composicao PQC (proporcao Classical vs PQC)
    4. Metricas de rotacao (numero de mensagens, ratio Classical/Hybrid)
    5. Overhead de tempo por fase (se disponivel)
    6. Correlacao bandwidth vs tempo (trade-off seguranca/desempenho)
    7. Interpretacao geral dos resultados
    """
    print("\n" + "="*80)
    print("RESUMO EXECUTIVO")
    print("="*80)
    
    print("\n1. OVERHEAD POR FASE - AGREGADO (Mediana)")
    print("-" * 40)
    
    for phase in ['Agreement', 'Initial_Distribution', 'Rotation']:
        if phase in results_bandwidth:
            df_phase = results_bandwidth[phase]
            
            if isinstance(df_phase, pd.DataFrame) and len(df_phase) > 0:
                # Calcular medianas agregadas
                classical_agg = df_phase['classical_median'].median()
                hybrid_agg = df_phase['hybrid_median'].median()
                overhead_agg = ((hybrid_agg - classical_agg) / classical_agg * 100) if classical_agg > 0 else 0
                
                # Pegar primeiro teste como representativo
                test_name = df_phase['test_name'].iloc[0]
                effect_label = df_phase['effect_label'].iloc[0]
                
                print(f"{phase:25s}: {overhead_agg:8.2f}% | "
                      f"Classical: {classical_agg:10.0f}B | "
                      f"Hybrid: {hybrid_agg:10.0f}B | "
                      f"Effect: {effect_label}")
    
    print("\n2. SIGNIFICANCIA ESTATISTICA (Holm-Bonferroni, alpha=0.05)")
    print("-" * 40)
    
    for phase in ['Agreement', 'Initial_Distribution', 'Rotation']:
        if phase in results_bandwidth:
            df_phase = results_bandwidth[phase]
            
            if isinstance(df_phase, pd.DataFrame) and len(df_phase) > 0:
                # Contar significativos
                n_sig = sum(df_phase['significant'])
                n_total = len(df_phase)
                
                print(f"{phase:25s}: {n_sig}/{n_total} significativos")
                
                for _, row in df_phase.iterrows():
                    sig_marker = "***" if row['significant'] else "n.s."
                    print(f"  {row['room_type']:20s}: {sig_marker:4s} | "
                          f"p_adj={row['p_adjusted']:.4e} | "
                          f"Teste: {row['test_name']}")
    
    print("\n3. COMPOSICAO PQC (Mediana)")
    print("-" * 40)
    
    for phase in ['Agreement', 'Setup', 'Rotation']:
        if phase in results_components:
            r = results_components[phase]
            print(f"{phase:20s}: Classical {r['classical_pct']:4.1f}% | PQC {r['pqc_pct']:4.1f}%")
    
    print("\n4. METRICAS DE ROTACAO")
    print("-" * 40)
    
    if results_rotation:
        print(f"Ratio mensagens (H/C): {results_rotation['ratio']:.2f}x")
        print(f"Classical (mediana):   {results_rotation['classical_msgs_median']:.0f} mensagens")
        print(f"Hybrid (mediana):      {results_rotation['hybrid_msgs_median']:.0f} mensagens")
    
    # NOVA SECAO: Metricas de tempo
    if results_time:
        print("\n5. OVERHEAD DE TEMPO (Mediana Agregada)")
        print("-" * 40)
        
        for phase in ['Setup', 'Rotation']:
            if phase in results_time:
                df_phase = results_time[phase]
                
                if isinstance(df_phase, pd.DataFrame) and len(df_phase) > 0:
                    classical_agg = df_phase['classical_median'].median()
                    hybrid_agg = df_phase['hybrid_median'].median()
                    overhead_agg = ((hybrid_agg - classical_agg) / classical_agg * 100) if classical_agg > 0 else 0
                    
                    effect_label = df_phase['effect_label'].iloc[0]
                    
                    print(f"{phase:25s}: {overhead_agg:8.2f}% | "
                          f"Classical: {classical_agg:10.2f}ms | "
                          f"Hybrid: {hybrid_agg:10.2f}ms | "
                          f"Effect: {effect_label}")
    
    # NOVA SECAO: Correlacao bandwidth vs tempo
    if correlations:
        print("\n6. CORRELACAO BANDWIDTH vs TEMPO")
        print("-" * 40)
        
        for phase, data in correlations.items():
            ratio = data['ratio']
            print(f"{phase:20s}: BW {data['bandwidth_overhead']:6.2f}x / Time {data['time_overhead']:4.2f}x = {ratio:6.2f}")
        
        print("\nInterpretacao:")
        print("  Ratio > 5: Bandwidth overhead >> Tempo overhead (operacoes rapidas, payloads grandes)")
        print("  Ratio 2-5: Bandwidth moderadamente > Tempo (equilibrio)")
        print("  Ratio < 2: Overheads proporcionais")
    
    print("\n7. INTERPRETACAO")
    print("-" * 40)
    print("BANDWIDTH:")
    print("  Agreement: Overhead alto (9.3x) devido ao Kyber768 KEM (800B)")
    print("  Setup: Overhead moderado (4.3x) devido ao Ratchet Key (1219B) + KEM (1088B)")
    print("  Rotation: Overhead moderado (4.3x) devido ao Ratchet Key (1219B)")
    print("    -> KEM adicional (1088B) apenas em forcamentos/mudanca de direcao")
    print("\nTEMPO:")
    print("  Setup: Overhead moderado (42%) - Kyber KeyGen rapido apesar de payload grande")
    print("  Rotation: Overhead moderado (65%) - Operacoes PQC mais lentas que Classical")
    print("\nTRADE-OFF:")
    print("  Setup: Ratio ~17 - Kyber gera chave grande (2.6KB) mas e rapido (~1.3ms)")
    print("  Rotation: Ratio ~2.2 - Operacoes PQC mais lentas, mas payload menor")
    print("\nPayload domina Classical (47%), Primitivos PQC dominam Hybrid (51%)")
    print("Overhead justificado pela seguranca pos-quantica (Kyber768 NIST Level 3)")


def save_paired_analysis_csv(results_bandwidth, results_components, csv_path):
    """
    Salva CSV estruturado com resultados da analise pareada.
    
    Gera arquivo .paired_analysis.csv com:
    - Uma linha por (fase, room_type)
    - Medianas Classical/Hybrid, deltas, overheads
    - Resultados de testes estatisticos (p-values, effect sizes)
    - Intervalos de confianca
    
    Formato compativel com scripts de visualizacao posteriores.
    
    Returns:
        DataFrame: resultados estruturados
    """
    rows = []
    
    # Processar resultados de bandwidth por fase
    for phase_name, df_phase in results_bandwidth.items():
        if not isinstance(df_phase, pd.DataFrame) or len(df_phase) == 0:
            continue
        
        # Iterar sobre cada room_type no DataFrame
        for _, row in df_phase.iterrows():
            result_row = {
                'phase': phase_name,
                'room_type': row['room_type'],
                'metric': f'bandwidth_{phase_name.lower().replace(" ", "_")}',
                'classical_median': row['classical_median'],
                'hybrid_median': row['hybrid_median'],
                'delta_median': row['delta_median'],
                'delta_iqr': row['delta_iqr'],
                'delta_p95': row['delta_p95'],
                'overhead_pct': row['overhead_pct'],
                'test_name': row['test_name'],
                'p_value': row['p_value'],
                'p_holm': row.get('p_adjusted', row['p_value']),
                'effect_size': row['effect_size'],
                'effect_magnitude': row['effect_label'],
                'ci_lower': row['ci_lower'],
                'ci_upper': row['ci_upper'],
                'n_pairs': row['n_pairs'],
                'n_clean': row['n_clean'],
                'is_normal': row['is_normal']
            }
            rows.append(result_row)
    
    # Criar DataFrame
    df_results = pd.DataFrame(rows)
    
    # Salvar CSV
    output_path = str(csv_path).replace('.csv', '.paired_analysis.csv')
    df_results.to_csv(output_path, index=False)
    
    print(f"\n[OK] CSV de analise pareada salvo: {output_path}")
    print(f"  Total de comparacoes: {len(df_results)}")
    
    return df_results


def main():
    if len(sys.argv) < 2:
        print("Uso: ./analyze_paired.py <csv_file>")
        sys.exit(1)
    
    csv_path = Path(sys.argv[1])
    
    if not csv_path.exists():
        print(f"ERRO: Arquivo nao encontrado: {csv_path}")
        sys.exit(1)
    
    print("="*80)
    print("ANALISE PAREADA: BANDWIDTH E TEMPO (CLASSICAL VS HYBRID)")
    print("="*80)
    print(f"\nArquivo: {csv_path}")
    print(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Carregar CSV
    df = pd.read_csv(csv_path)
    
    print(f"\nDimensoes: {df.shape[0]} linhas x {df.shape[1]} colunas")
    print(f"Colunas: {', '.join(df.columns[:10])}...")
    
    # Analise 1: Bandwidth por fase (Agreement, Initial Distribution, Rotation)
    results_bandwidth = analyze_bandwidth_by_phase(df)
    
    # Analise 2: Decomposicao PQC (Classical vs PQC)
    results_components = analyze_pqc_components(df)
    
    # Analise 3: Metricas operacionais de rotacao
    results_rotation = analyze_rotation_metrics(df)
    
    # Analise 4: Tempo por fase
    results_time = None
    correlations = None
    
    if 'setup_time_ms' in df.columns and 'rotation_time_ms' in df.columns:
        print("\n" + "="*80)
        print("METRICAS DE TEMPO DETECTADAS - EXECUTANDO ANALISE TEMPORAL")
        print("="*80)
        
        # Analise 4: Tempo por fase
        results_time = analyze_time_by_phase(df)
        
        # Analise 5: Correlacao bandwidth vs tempo
        correlations = analyze_bandwidth_time_correlation(df, results_bandwidth, results_time)
    else:
        print("\n" + "="*80)
        print("AVISO: Metricas de tempo nao encontradas no CSV")
        print("="*80)
        print("Esperadas: setup_time_ms, rotation_time_ms")
        print("Analise temporal PULADA - apenas bandwidth/rotacao processados")
    
    # Resumo consolidado (bandwidth + tempo se disponivel)
    generate_summary(results_bandwidth, results_components, results_rotation, results_time, correlations)
    
    # Salvar CSV estruturado para visualizacao
    print("\n" + "="*80)
    print("GERANDO ARTEFATOS ADICIONAIS")
    print("="*80)
    
    df_results = save_paired_analysis_csv(results_bandwidth, results_components, csv_path)
    
    print("\n" + "="*80)
    print("ANALISE CONCLUIDA")
    print("="*80)
    print(f"\nArquivos gerados:")
    print(f"  • {csv_path.name.replace('.csv', '.paired_analysis.csv')} (CSV estruturado)")
    print(f"\nPara gerar tabelas/graficos LaTeX e visualizacoes, execute:")
    print(f"  python scripts/generate_bandwidth_components_tables_and_plots.py {csv_path}")


if __name__ == '__main__':
    main()
