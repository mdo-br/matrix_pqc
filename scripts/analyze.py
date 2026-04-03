#!/usr/bin/env python3
"""
Análise estatística pareada e geração de artefatos do artigo SBRC 2026.

Script unificado que realiza:
  1. Análise estatística pareada (Classical vs Hybrid)
     - Bandwidth por fase (Agreement, Initial Distribution, Rotation)
     - Composição PQC (proporção Classical vs PQC)
     - Métricas de rotação (mensagens, forçamentos)
     - Tempo por fase (Setup, Rotation)
     - Correlação Bandwidth × Tempo
  2. Geração de artefatos referenciados no artigo
     - fig_overhead_comparison_bandwidth_time.png  (Figura 3)
     - fig_policy_tradeoff_smallgroup.png          (Figura 4)
     - tab_detailed_phase_room_policy.tex          (Tabela 3)
  3. Resumo executivo e CSV estruturado

Testes estatísticos:
  - Normalidade: Shapiro-Wilk
  - Pareado: paired t-test (normal) ou Wilcoxon signed-rank (não-normal)
  - Effect size: Cohen's d (paramétrico) ou Cliff's delta (não-paramétrico)
  - IC 95%: t-Student (normal) ou Bootstrap 10.000 reamostragens (não-normal)
  - Correção múltipla: Holm-Bonferroni

Uso:
    python scripts/analyze.py results/user_profile_runs_TIMESTAMP_all_policies.csv

Saídas:
    results/*.paired_analysis.csv          — CSV estruturado com resultados
    tables_and_plots/fig_*.png             — Figuras do artigo
    tables_and_plots/tab_*.tex             — Tabelas do artigo
"""

import sys
import warnings
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy import stats

warnings.filterwarnings('ignore', category=RuntimeWarning)

# Estilo de gráficos
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")


# =============================================================================
# Funções utilitárias estatísticas
# =============================================================================

def shapiro_test(data, alpha=0.05):
    """Testa normalidade com Shapiro-Wilk."""
    if len(data) < 3:
        return False, np.nan, "n < 3 (insuficiente)"
    if len(data) > 5000:
        return False, np.nan, "n > 5000 (usa Wilcoxon)"
    stat, p = stats.shapiro(data)
    return p > alpha, p, "Normal" if p > alpha else "Nao-normal"


def cohens_d(group1, group2):
    """Cohen's d (effect size paramétrico)."""
    n1, n2 = len(group1), len(group2)
    var1, var2 = np.var(group1, ddof=1), np.var(group2, ddof=1)
    pooled_std = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))
    if pooled_std == 0:
        return 0.0
    return (np.mean(group1) - np.mean(group2)) / pooled_std


def cliffs_delta(group1, group2):
    """Cliff's delta (effect size não-paramétrico)."""
    n1, n2 = len(group1), len(group2)
    dominance = sum(
        sum(1 for b in group2 if a > b) - sum(1 for b in group2 if a < b)
        for a in group1
    )
    return dominance / (n1 * n2) if (n1 * n2) > 0 else 0.0


def bootstrap_ci_median(data, confidence=0.95, n_bootstrap=10000):
    """IC bootstrap para mediana."""
    if len(data) < 2:
        return np.nan, np.nan
    rng = np.random.RandomState(42)
    medians = [np.median(rng.choice(data, size=len(data), replace=True))
               for _ in range(n_bootstrap)]
    alpha = 1 - confidence
    return np.percentile(medians, 100 * alpha / 2), np.percentile(medians, 100 * (1 - alpha / 2))


def holm_bonferroni_correction(p_values):
    """Correção Holm-Bonferroni para comparações múltiplas."""
    p_values = np.asarray(p_values, dtype=float)
    n = len(p_values)
    sorted_indices = np.argsort(p_values)
    adjusted = np.zeros(n)
    for rank, idx in enumerate(sorted_indices):
        adjusted[idx] = min(1.0, p_values[idx] * (n - rank))
    for i in range(1, n):
        prev_idx = sorted_indices[i - 1]
        curr_idx = sorted_indices[i]
        adjusted[curr_idx] = max(adjusted[curr_idx], adjusted[prev_idx])
    return adjusted


def detect_outliers_iqr(data, threshold=1.5):
    """Detecta outliers pelo método IQR."""
    q1 = np.percentile(data, 25)
    q3 = np.percentile(data, 75)
    iqr = q3 - q1
    return (data < q1 - threshold * iqr) | (data > q3 + threshold * iqr)


# =============================================================================
# Análise pareada por tipo de sala
# =============================================================================

def paired_analysis_by_room_type(df, metric, metric_name):
    """Análise pareada agrupada por tipo de sala."""
    results = []
    if 'room_type' not in df.columns:
        print(f"AVISO: Coluna 'room_type' não encontrada")
        return pd.DataFrame()

    for room_type in sorted(df['room_type'].unique()):
        df_room = df[df['room_type'] == room_type].copy()
        classical = df_room[df_room['repeat_id'] == 0][metric].values
        hybrid = df_room[df_room['repeat_id'] == 1][metric].values
        n_pairs = min(len(classical), len(hybrid))
        if n_pairs == 0:
            continue
        classical = classical[:n_pairs]
        hybrid = hybrid[:n_pairs]
        diffs = hybrid - classical

        # Remover outliers apenas para métricas de tempo
        if 'bandwidth' in metric or 'bytes' in metric:
            diffs_clean, classical_clean, hybrid_clean = diffs, classical, hybrid
            n_outliers = 0
        else:
            mask = detect_outliers_iqr(diffs)
            diffs_clean = diffs[~mask]
            classical_clean = classical[~mask]
            hybrid_clean = hybrid[~mask]
            n_outliers = int(np.sum(mask))

        n_clean = len(diffs_clean)
        if n_clean < 3:
            continue

        delta_median = np.median(diffs_clean)
        ci_lower, ci_upper = bootstrap_ci_median(diffs_clean)
        classical_median = np.median(classical_clean)
        overhead_pct = (delta_median / classical_median * 100) if classical_median > 0 else 0

        _, p_shapiro = stats.shapiro(diffs_clean) if len(diffs_clean) >= 3 else (None, 0)
        is_normal = p_shapiro > 0.05 if p_shapiro is not None else False

        if is_normal and n_clean >= 5:
            _, p_value = stats.ttest_rel(hybrid_clean, classical_clean)
            test_name = "paired_t"
            effect_size = cohens_d(classical_clean, hybrid_clean)
            effect_label = "Cohen's d"
        else:
            _, p_value = stats.wilcoxon(hybrid_clean, classical_clean, alternative='two-sided')
            test_name = "Wilcoxon"
            effect_size = cliffs_delta(classical_clean, hybrid_clean)
            effect_label = "Cliff's delta"

        results.append({
            'room_type': room_type, 'metric': metric_name,
            'n_pairs': n_pairs, 'n_clean': n_clean, 'n_outliers': n_outliers,
            'classical_median': classical_median,
            'hybrid_median': np.median(hybrid_clean),
            'delta_median': delta_median,
            'delta_iqr': np.percentile(diffs_clean, 75) - np.percentile(diffs_clean, 25),
            'delta_p95': np.percentile(diffs_clean, 95),
            'delta_p99': np.percentile(diffs_clean, 99),
            'ci_lower': ci_lower, 'ci_upper': ci_upper,
            'overhead_pct': overhead_pct,
            'delta_mean': np.mean(diffs_clean) if is_normal else None,
            'delta_std': np.std(diffs_clean, ddof=1) if is_normal else None,
            'p_shapiro': p_shapiro, 'is_normal': is_normal,
            'test_name': test_name, 'p_value': p_value,
            'effect_size': effect_size, 'effect_label': effect_label,
        })

    return pd.DataFrame(results)


# =============================================================================
# Análise 1: Bandwidth por fase
# =============================================================================

def analyze_bandwidth_by_phase(df):
    """Análise de largura de banda por fase (Agreement, Initial Distribution, Rotation)."""
    print("\n" + "=" * 80)
    print("ANÁLISE DE LARGURA DE BANDA POR FASE")
    print("=" * 80)

    required = ['batch_id', 'pair_id', 'repeat_id', 'crypto_mode', 'room_type']
    if any(c not in df.columns for c in required):
        print(f"ERRO: Colunas ausentes")
        return {}

    print(f"\nEstrutura do CSV:")
    print(f"  Total de linhas: {len(df)}")
    print(f"  Distribuição:")
    print(df.groupby(['room_type', 'crypto_mode']).size())

    phases = {
        'Agreement': 'bandwidth_agreement',
        'Initial_Distribution': 'bandwidth_initial_distribution',
        'Rotation': 'bandwidth_rotation',
    }

    results = {}
    all_p, test_names = [], []

    for phase_name, col in phases.items():
        print(f"\n{'-' * 80}\nFASE: {phase_name}\n{'-' * 80}")
        if col not in df.columns:
            print(f"AVISO: Coluna '{col}' não encontrada")
            continue

        df_phase = paired_analysis_by_room_type(df, col, phase_name)
        if len(df_phase) == 0:
            continue

        for _, row in df_phase.iterrows():
            print(f"\n{row['room_type']} ({row['n_clean']} pares):")
            print(f"  Classical: {row['classical_median']:.0f}B")
            print(f"  Hybrid:    {row['hybrid_median']:.0f}B")
            print(f"  Overhead:  {row['overhead_pct']:+.2f}%")
            print(f"  Teste:     {row['test_name']} (p={row['p_value']:.4e})")
            print(f"  Effect:    {row['effect_size']:.3f} ({row['effect_label']})")

        all_p.extend(df_phase['p_value'].values)
        test_names.extend([f"{phase_name}_{rt}" for rt in df_phase['room_type'].values])
        results[phase_name] = df_phase

    if all_p:
        p_adj = holm_bonferroni_correction(all_p)
        print(f"\n{'-' * 80}\nCORREÇÃO HOLM-BONFERRONI\n{'-' * 80}")
        for i, name in enumerate(test_names):
            sig = "***" if p_adj[i] < 0.05 else "n.s."
            print(f"{name:30s} | p_raw: {all_p[i]:.4e} | p_adj: {p_adj[i]:.4e} | {sig}")
        idx = 0
        for df_ph in results.values():
            n = len(df_ph)
            df_ph['p_adjusted'] = p_adj[idx:idx + n]
            df_ph['significant'] = df_ph['p_adjusted'] < 0.05
            idx += n

    return results


# =============================================================================
# Análise 2: Composição PQC
# =============================================================================

def analyze_pqc_components(df):
    """Análise de decomposição de bandwidth em componentes Classical e PQC."""
    print("\n" + "=" * 80)
    print("ANÁLISE DE COMPONENTES PQC")
    print("=" * 80)

    cols_c = ['bandwidth_agreement_classical', 'bandwidth_initial_distribution_classical',
              'bandwidth_rotation_classical']
    cols_p = ['bandwidth_agreement_pqc', 'bandwidth_initial_distribution_pqc',
              'bandwidth_rotation_pqc']

    if not all(c in df.columns for c in cols_c + cols_p):
        print("\nAVISO: CSV não contém colunas detalhadas de componentes Classical/PQC")
        return {}

    print(f"\nAgregando componentes por run...")
    df_agg = df.groupby(
        ['batch_id', 'pair_id', 'repeat_id', 'crypto_mode'], as_index=False
    )[cols_c + cols_p].sum()
    df_hybrid = df_agg[df_agg['crypto_mode'] == 'Hybrid'].copy()

    if len(df_hybrid) == 0:
        print("\nAVISO: Nenhum run Hybrid encontrado")
        return {}

    print(f"N runs Hybrid agregados: {len(df_hybrid)}")

    phases = {
        'Agreement': ('bandwidth_agreement_classical', 'bandwidth_agreement_pqc'),
        'Setup': ('bandwidth_initial_distribution_classical', 'bandwidth_initial_distribution_pqc'),
        'Rotation': ('bandwidth_rotation_classical', 'bandwidth_rotation_pqc'),
    }

    results = {}
    for phase, (col_c, col_p) in phases.items():
        print(f"\n{'-' * 80}\nFase: {phase}\n{'-' * 80}")
        c_bytes = df_hybrid[col_c].dropna()
        p_bytes = df_hybrid[col_p].dropna()
        if len(c_bytes) == 0 or len(p_bytes) == 0:
            continue
        c_med = np.median(c_bytes)
        p_med = np.median(p_bytes)
        total = c_med + p_med
        c_pct = (c_med / total * 100) if total > 0 else 0
        p_pct = (p_med / total * 100) if total > 0 else 0
        print(f"\nComponente Classical: {c_med:.0f}B ({c_pct:.1f}%)")
        print(f"Componente PQC:       {p_med:.0f}B ({p_pct:.1f}%)")
        print(f"Total:                {total:.0f}B")
        results[phase] = {
            'classical_median': c_med, 'pqc_median': p_med,
            'total_median': total, 'classical_pct': c_pct, 'pqc_pct': p_pct,
        }

    return results


# =============================================================================
# Análise 3: Métricas de rotação
# =============================================================================

def analyze_rotation_metrics(df):
    """Análise de métricas operacionais de rotação."""
    print("\n" + "=" * 80)
    print("ANÁLISE DE MÉTRICAS DE ROTAÇÃO")
    print("=" * 80)

    if 'num_rotation_messages' not in df.columns:
        print("\nAVISO: Coluna 'num_rotation_messages' não encontrada")
        return {}

    agg_cols = [c for c in ['num_rotation_messages', 'bandwidth_rotation',
                            'num_asymmetric_advances'] if c in df.columns]

    print(f"\nAgregando métricas de rotação por run...")
    df_agg = df.groupby(
        ['batch_id', 'pair_id', 'repeat_id', 'crypto_mode'], as_index=False
    )[agg_cols].sum()

    df_c = df_agg[df_agg['crypto_mode'] == 'Classical']
    df_h = df_agg[df_agg['crypto_mode'] == 'Hybrid']

    if len(df_c) == 0 or len(df_h) == 0:
        print("\nAVISO: Dados Classical ou Hybrid ausentes")
        return {}

    c_msgs = df_c['num_rotation_messages'].dropna()
    h_msgs = df_h['num_rotation_messages'].dropna()

    print(f"\nNúmero de Mensagens de Rotação:")
    print(f"Classical - Mediana: {np.median(c_msgs):.0f} | Média: {np.mean(c_msgs):.1f}")
    print(f"Hybrid    - Mediana: {np.median(h_msgs):.0f} | Média: {np.mean(h_msgs):.1f}")

    ratio = np.median(h_msgs) / np.median(c_msgs) if np.median(c_msgs) > 0 else 0
    print(f"Ratio Hybrid/Classical: {ratio:.2f}x")
    print(f"{'OK' if abs(ratio - 1.0) <= 0.05 else 'AVISO'}: "
          f"Ratio {'próximo' if abs(ratio - 1.0) <= 0.05 else 'diferente'} de 1.0x")

    if 'num_asymmetric_advances' in df.columns:
        c_forces = df_c['num_asymmetric_advances'].dropna()
        h_forces = df_h['num_asymmetric_advances'].dropna()
        print(f"\nForçamentos Assimétricos:")
        print(f"Classical - Mediana: {np.median(c_forces):.0f} | Média: {np.mean(c_forces):.1f}")
        print(f"Hybrid    - Mediana: {np.median(h_forces):.0f} | Média: {np.mean(h_forces):.1f}")

    return {
        'classical_msgs_median': np.median(c_msgs),
        'hybrid_msgs_median': np.median(h_msgs),
        'ratio': ratio,
    }


# =============================================================================
# Análise 4: Tempo por fase
# =============================================================================

def analyze_time_by_phase(df):
    """Análise de tempo por fase (Setup, Rotation)."""
    print("\n" + "=" * 80)
    print("ANÁLISE DE TEMPO POR FASE")
    print("=" * 80)

    required = ['batch_id', 'pair_id', 'repeat_id', 'crypto_mode', 'room_type']
    if any(c not in df.columns for c in required):
        print(f"ERRO: Colunas ausentes")
        return {}

    time_cols = ['setup_time_ms', 'rotation_time_ms']
    if any(c not in df.columns for c in time_cols):
        print(f"ERRO: Métricas de tempo ausentes")
        return {}

    print(f"\nEstrutura do CSV:")
    print(f"  Total de linhas: {len(df)}")
    print(f"  Distribuição:")
    print(df.groupby(['room_type', 'crypto_mode']).size())

    phases = {
        'Setup': 'setup_time_ms',
        'Rotation': 'rotation_time_ms',
    }

    results = {}
    all_p, test_names = [], []

    for phase_name, col in phases.items():
        print(f"\n{'-' * 80}\nFASE: {phase_name}\n{'-' * 80}")
        if col not in df.columns:
            continue

        df_phase = paired_analysis_by_room_type(df, col, phase_name)
        if len(df_phase) == 0:
            continue

        for _, row in df_phase.iterrows():
            print(f"\n{row['room_type']} ({row['n_clean']} pares):")
            print(f"  Classical: {row['classical_median']:.2f}ms")
            print(f"  Hybrid:    {row['hybrid_median']:.2f}ms")
            print(f"  Overhead:  {row['overhead_pct']:+.2f}%")
            print(f"  Teste:     {row['test_name']} (p={row['p_value']:.4e})")
            print(f"  Effect:    {row['effect_size']:.3f} ({row['effect_label']})")

        all_p.extend(df_phase['p_value'].values)
        test_names.extend([f"{phase_name}_{rt}" for rt in df_phase['room_type'].values])
        results[phase_name] = df_phase

    if all_p:
        p_adj = holm_bonferroni_correction(all_p)
        print(f"\n{'-' * 80}\nCORREÇÃO HOLM-BONFERRONI (TEMPO)\n{'-' * 80}")
        for i, name in enumerate(test_names):
            sig = "***" if p_adj[i] < 0.05 else "n.s."
            print(f"{name:30s} | p_raw: {all_p[i]:.4e} | p_adj: {p_adj[i]:.4e} | {sig}")
        idx = 0
        for df_ph in results.values():
            n = len(df_ph)
            df_ph['p_adjusted'] = p_adj[idx:idx + n]
            df_ph['significant'] = df_ph['p_adjusted'] < 0.05
            idx += n

    return results


# =============================================================================
# Análise 5: Correlação Bandwidth × Tempo
# =============================================================================

def analyze_bandwidth_time_correlation(df, results_bw, results_time):
    """Correlação entre overhead de bandwidth e de tempo."""
    print("\n" + "=" * 80)
    print("ANÁLISE DE CORRELAÇÃO: BANDWIDTH vs TEMPO")
    print("=" * 80)

    if not results_bw or not results_time:
        print("\nAVISO: Resultados insuficientes para análise de correlação")
        return {}

    print("\nOverhead comparativo (Mediana Agregada):")
    print("-" * 60)
    print(f"{'Fase':<20s} {'Bandwidth':>12s} {'Tempo':>12s} {'Ratio':>10s}")
    print("-" * 60)

    correlations = {}

    # Setup (Agreement + Initial Distribution)
    if all(k in results_bw for k in ('Agreement', 'Initial_Distribution')) and 'Setup' in results_time:
        bw_agr = results_bw['Agreement']
        bw_init = results_bw['Initial_Distribution']
        t_setup = results_time['Setup']
        if all(isinstance(x, pd.DataFrame) and len(x) > 0 for x in [bw_agr, bw_init, t_setup]):
            bw_agg = ((bw_agr['hybrid_median'].sum() + bw_init['hybrid_median'].sum()) /
                      (bw_agr['classical_median'].sum() + bw_init['classical_median'].sum()))
            t_agg = t_setup['hybrid_median'].sum() / t_setup['classical_median'].sum()
            ratio = bw_agg / t_agg if t_agg > 0 else 0
            print(f"{'Setup (Agr+Init)':<20s} {bw_agg:>11.2f}x {t_agg:>11.2f}x {ratio:>9.2f}x")
            correlations['Setup'] = {
                'bandwidth_overhead': bw_agg, 'time_overhead': t_agg, 'ratio': ratio,
            }

    # Rotation
    if 'Rotation' in results_bw and 'Rotation' in results_time:
        bw_rot = results_bw['Rotation']
        t_rot = results_time['Rotation']
        if isinstance(bw_rot, pd.DataFrame) and isinstance(t_rot, pd.DataFrame):
            if len(bw_rot) > 0 and len(t_rot) > 0:
                bw_agg = bw_rot['hybrid_median'].sum() / bw_rot['classical_median'].sum()
                t_agg = t_rot['hybrid_median'].sum() / t_rot['classical_median'].sum()
                ratio = bw_agg / t_agg if t_agg > 0 else 0
                print(f"{'Rotation':<20s} {bw_agg:>11.2f}x {t_agg:>11.2f}x {ratio:>9.2f}x")
                correlations['Rotation'] = {
                    'bandwidth_overhead': bw_agg, 'time_overhead': t_agg, 'ratio': ratio,
                }

    print("-" * 60)
    print("\nInterpretação:")
    print("  Ratio > 1.0: Bandwidth overhead > Tempo overhead")
    print("  Ratio < 1.0: Tempo overhead > Bandwidth overhead")
    print("  Ratio ~ 1.0: Overheads proporcionais")

    return correlations


# =============================================================================
# Resumo executivo
# =============================================================================

def generate_summary(results_bw, results_comp, results_rot,
                     results_time=None, correlations=None):
    """Resumo executivo consolidado."""
    print("\n" + "=" * 80)
    print("RESUMO EXECUTIVO")
    print("=" * 80)

    # 1. Overhead por fase
    print("\n1. OVERHEAD POR FASE - AGREGADO (Mediana)")
    print("-" * 40)
    for phase in ['Agreement', 'Initial_Distribution', 'Rotation']:
        if phase in results_bw:
            df_ph = results_bw[phase]
            if isinstance(df_ph, pd.DataFrame) and len(df_ph) > 0:
                c_agg = df_ph['classical_median'].median()
                h_agg = df_ph['hybrid_median'].median()
                oh = ((h_agg - c_agg) / c_agg * 100) if c_agg > 0 else 0
                lbl = df_ph['effect_label'].iloc[0]
                print(f"{phase:25s}: {oh:8.2f}% | Classical: {c_agg:10.0f}B | "
                      f"Hybrid: {h_agg:10.0f}B | Effect: {lbl}")

    # 2. Significância
    print("\n2. SIGNIFICÂNCIA ESTATÍSTICA (Holm-Bonferroni, alpha=0.05)")
    print("-" * 40)
    for phase in ['Agreement', 'Initial_Distribution', 'Rotation']:
        if phase in results_bw:
            df_ph = results_bw[phase]
            if isinstance(df_ph, pd.DataFrame) and len(df_ph) > 0:
                n_sig = sum(df_ph['significant'])
                print(f"{phase:25s}: {n_sig}/{len(df_ph)} significativos")
                for _, row in df_ph.iterrows():
                    sig = "***" if row['significant'] else "n.s."
                    print(f"  {row['room_type']:20s}: {sig:4s} | p_adj={row['p_adjusted']:.4e} | "
                          f"Teste: {row['test_name']}")

    # 3. Composição PQC
    print("\n3. COMPOSIÇÃO PQC (Mediana)")
    print("-" * 40)
    for phase in ['Agreement', 'Setup', 'Rotation']:
        if phase in results_comp:
            r = results_comp[phase]
            print(f"{phase:20s}: Classical {r['classical_pct']:4.1f}% | PQC {r['pqc_pct']:4.1f}%")

    # 4. Rotação
    print("\n4. MÉTRICAS DE ROTAÇÃO")
    print("-" * 40)
    if results_rot:
        print(f"Ratio mensagens (H/C): {results_rot['ratio']:.2f}x")
        print(f"Classical (mediana):   {results_rot['classical_msgs_median']:.0f} mensagens")
        print(f"Hybrid (mediana):      {results_rot['hybrid_msgs_median']:.0f} mensagens")

    # 5. Tempo
    if results_time:
        print("\n5. OVERHEAD DE TEMPO (Sum-of-Medians)")
        print("-" * 40)
        for phase in ['Setup', 'Rotation']:
            if phase in results_time:
                df_ph = results_time[phase]
                if isinstance(df_ph, pd.DataFrame) and len(df_ph) > 0:
                    c_agg = df_ph['classical_median'].sum()
                    h_agg = df_ph['hybrid_median'].sum()
                    oh = ((h_agg - c_agg) / c_agg * 100) if c_agg > 0 else 0
                    lbl = df_ph['effect_label'].iloc[0]
                    print(f"{phase:25s}: {oh:8.2f}% | Classical: {c_agg:10.2f}ms | "
                          f"Hybrid: {h_agg:10.2f}ms | Effect: {lbl}")

    # 6. Correlação
    if correlations:
        print("\n6. CORRELAÇÃO BANDWIDTH vs TEMPO")
        print("-" * 40)
        for phase, data in correlations.items():
            print(f"{phase:20s}: BW {data['bandwidth_overhead']:6.2f}x / "
                  f"Time {data['time_overhead']:4.2f}x = {data['ratio']:6.2f}")
        print("\nInterpretação:")
        print("  Ratio > 5: Bandwidth >> Tempo (operações rápidas, payloads grandes)")
        print("  Ratio 2-5: Bandwidth moderadamente > Tempo")
        print("  Ratio < 2: Overheads proporcionais")


# =============================================================================
# Geração de CSV estruturado
# =============================================================================

def save_paired_analysis_csv(results_bw, csv_path):
    """Salva CSV estruturado com resultados da análise pareada."""
    rows = []
    for phase_name, df_phase in results_bw.items():
        if not isinstance(df_phase, pd.DataFrame) or len(df_phase) == 0:
            continue
        for _, row in df_phase.iterrows():
            rows.append({
                'phase': phase_name, 'room_type': row['room_type'],
                'metric': f'bandwidth_{phase_name.lower().replace(" ", "_")}',
                'classical_median': row['classical_median'],
                'hybrid_median': row['hybrid_median'],
                'delta_median': row['delta_median'],
                'delta_iqr': row['delta_iqr'], 'delta_p95': row['delta_p95'],
                'overhead_pct': row['overhead_pct'],
                'test_name': row['test_name'], 'p_value': row['p_value'],
                'p_holm': row.get('p_adjusted', row['p_value']),
                'effect_size': row['effect_size'],
                'effect_magnitude': row['effect_label'],
                'ci_lower': row['ci_lower'], 'ci_upper': row['ci_upper'],
                'n_pairs': row['n_pairs'], 'n_clean': row['n_clean'],
                'is_normal': row['is_normal'],
            })

    df_out = pd.DataFrame(rows)
    out_path = str(csv_path).replace('.csv', '.paired_analysis.csv')
    df_out.to_csv(out_path, index=False)
    print(f"\n[OK] CSV de análise pareada salvo: {out_path}")
    print(f"  Total de comparações: {len(df_out)}")
    return df_out


# =============================================================================
# Geração de artefatos do artigo
# =============================================================================

def generate_figure_overhead_bw_vs_time(df, output_dir):
    """
    Figura 3 do artigo: gráfico de barras horizontais duplo
    comparando overhead de Bandwidth (esquerda) vs Tempo (direita) por fase.
    """
    output_file = output_dir / "fig_overhead_comparison_bandwidth_time.png"
    print(f"\n{'-' * 80}")
    print("Gerando Figura 3: Comparação BW vs Tempo")
    print(f"{'-' * 80}")

    df_c = df[df['crypto_mode'] == 'Classical']
    df_h = df[df['crypto_mode'] == 'Hybrid']

    # --- Bandwidth (mediana global — determinístico, proporcional a N) ---
    setup_bw_c = (df_c['bandwidth_agreement'] + df_c['bandwidth_initial_distribution']).median()
    setup_bw_h = (df_h['bandwidth_agreement'] + df_h['bandwidth_initial_distribution']).median()
    rot_bw_c = df_c['bandwidth_rotation'].median()
    rot_bw_h = df_h['bandwidth_rotation'].median()
    enc_bw_c = df_c['bandwidth_megolm_messages'].median() if 'bandwidth_megolm_messages' in df_c.columns else 0
    enc_bw_h = df_h['bandwidth_megolm_messages'].median() if 'bandwidth_megolm_messages' in df_h.columns else 0

    bw_overheads = [
        ((setup_bw_h - setup_bw_c) / setup_bw_c * 100) if setup_bw_c > 0 else 0,
        ((rot_bw_h - rot_bw_c) / rot_bw_c * 100) if rot_bw_c > 0 else 0,
        ((enc_bw_h - enc_bw_c) / enc_bw_c * 100) if enc_bw_c > 0 else 0,
    ]

    # --- Tempo (agregação balanceada: sum-of-medians por tipo de sala) ---
    room_types = sorted(df['room_type'].unique()) if 'room_type' in df.columns else []

    def weighted_time_overhead(metric):
        total_c, total_h = 0.0, 0.0
        for room in room_types:
            rc = df_c[df_c['room_type'] == room]
            rh = df_h[df_h['room_type'] == room]
            if len(rc) == 0 or len(rh) == 0:
                continue
            total_c += rc[metric].median()
            total_h += rh[metric].median()
        return ((total_h - total_c) / total_c * 100) if total_c > 0 else 0

    time_overheads = [
        weighted_time_overhead('setup_time_ms'),
        weighted_time_overhead('rotation_time_ms'),
        weighted_time_overhead('megolm_encrypt_time_ms') if 'megolm_encrypt_time_ms' in df.columns else 0,
    ]

    # --- Plot ---
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 4), sharey=True)
    phases = ['Setup\n(Acordo + Dist.)', 'Rotações', 'Criptografia\n(Megolm)']
    y_pos = np.arange(len(phases))
    colors = ['#FF8C42', '#FFD93D', '#6BCF7F']

    for ax, overheads, xlabel, title in [
        (ax1, bw_overheads, 'Overhead de Largura de Banda (%)', 'Largura de Banda'),
        (ax2, time_overheads, 'Overhead de Tempo (%)', 'Tempo de Processamento'),
    ]:
        bars = ax.barh(y_pos, overheads, height=0.6, color=colors,
                       edgecolor='black', linewidth=1.5)
        ax.set_xlabel(xlabel, fontsize=14, fontweight='bold')
        ax.set_title(title, fontsize=15, fontweight='bold', pad=15)
        ax.set_xlim(0, 600)
        ax.grid(axis='x', alpha=0.3, linestyle='--')
        ax.tick_params(axis='x', labelsize=13)
        for bar, val in zip(bars, overheads):
            ax.text(val + 15, bar.get_y() + bar.get_height() / 2,
                    f'{val:.0f}%', va='center', ha='left', fontsize=13, fontweight='bold')

    ax1.set_yticks(y_pos)
    ax1.set_yticklabels(phases, fontsize=13)
    ax1.invert_yaxis()

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"[OK] Figura salva: {output_file}")
    print(f"  Largura de Banda:  Setup={bw_overheads[0]:.0f}%  "
          f"Rotações={bw_overheads[1]:.0f}%  Criptografia={bw_overheads[2]:.1f}%")
    print(f"  Tempo:             Setup={time_overheads[0]:.0f}%  "
          f"Rotações={time_overheads[1]:.0f}%  Criptografia={time_overheads[2]:.1f}%")
    if time_overheads[0] > 0 and time_overheads[1] > 0:
        print(f"  Ratio BW/Tempo:    Setup={bw_overheads[0] / time_overheads[0]:.1f}×  "
              f"Rotações={bw_overheads[1] / time_overheads[1]:.1f}×")

    return output_file


def generate_figure_policy_tradeoff(df, output_dir):
    """
    Figura 4 do artigo: trade-off segurança vs custo para SmallGroup (N=7).
    Barras = overhead de rotações, linha = janela de segurança.
    """
    output_file = output_dir / "fig_policy_tradeoff_smallgroup.png"
    print(f"\n{'-' * 80}")
    print("Gerando Figura 4: Trade-off para SmallGroup (N=7)")
    print(f"{'-' * 80}")

    # Derivar N do CSV
    df_small = df[df['room_type'] == 'SmallGroup']
    if len(df_small) == 0:
        print("AVISO: Nenhum dado de SmallGroup encontrado!")
        return None

    policies = ['Paranoid', 'PQ3', 'Balanced', 'Relaxed']
    intervals = {'Paranoid': 25, 'PQ3': 50, 'Balanced': 100, 'Relaxed': 250}

    rows = []
    for policy in policies:
        dp = df_small[df_small['rotation_policy'] == policy]
        dc = dp[dp['crypto_mode'] == 'Classical']
        dh = dp[dp['crypto_mode'] == 'Hybrid']
        if len(dh) == 0:
            continue
        rot_oh = dh['bandwidth_rotation'].median() - dc['bandwidth_rotation'].median()
        sec_win = intervals[policy]
        rows.append({'policy': policy, 'interval': sec_win,
                     'rot_bw_overhead_kb': rot_oh / 1024, 'security_window': sec_win})
        print(f"\n{policy:10s} (janela: {sec_win} msgs):")
        print(f"  Classical:     {dc['bandwidth_rotation'].median() / 1024:8.1f} kB")
        print(f"  Hybrid:        {dh['bandwidth_rotation'].median() / 1024:8.1f} kB")
        print(f"  Overhead (H-C): {rot_oh / 1024:8.1f} kB")

    if not rows:
        print("ERRO: Nenhum resultado válido para plotar!")
        return None

    df_r = pd.DataFrame(rows)
    fig, ax1 = plt.subplots(figsize=(10, 7))

    x = np.arange(len(df_r))
    rot_oh_vals = df_r['rot_bw_overhead_kb'].values
    sec_vals = df_r['security_window'].values
    pol_names = df_r['policy'].values
    int_vals = df_r['interval'].values

    color1, color2 = '#e74c3c', '#27ae60'
    bars = ax1.bar(x, rot_oh_vals, width=0.7, color=color1, alpha=0.7,
                   edgecolor='black', linewidth=1.5, label='Overhead Rotações')
    ax1.set_xlabel('Política de Rotação', fontsize=15, fontweight='bold')
    ax1.set_ylabel('Overhead Acumulado de Rotações (kB)', fontsize=15,
                   fontweight='bold', color=color1)
    ax1.tick_params(axis='y', labelcolor=color1, labelsize=13)
    ax1.tick_params(axis='x', labelsize=13)
    ax1.set_xticks(x)
    ax1.set_xticklabels([f"{p}\n({i} msgs)" for p, i in zip(pol_names, int_vals)], fontsize=13)
    ax1.set_xlim(-0.6, len(pol_names) - 0.4)
    ax1.set_ylim(0, rot_oh_vals.max() * 1.15)
    for bar in bars:
        h = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width() / 2., h,
                 f'{h:.1f}kB'.replace('.', ','),
                 ha='center', va='bottom', fontsize=14, fontweight='bold', color=color1)

    ax2 = ax1.twinx()
    ax2.plot(x, sec_vals, color=color2, marker='o', markersize=12, linewidth=3,
             label='Janela de Segurança', linestyle='--')
    ax2.set_ylabel('Janela de Segurança (mensagens)', fontsize=15,
                   fontweight='bold', color=color2)
    ax2.tick_params(axis='y', labelcolor=color2, labelsize=13)
    for i, s in enumerate(sec_vals):
        ax2.text(i, s, f'{s} msgs', ha='center', va='bottom', fontsize=14,
                 fontweight='bold', color=color2,
                 bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

    ax1.grid(False)
    ax2.grid(False)
    l1, lb1 = ax1.get_legend_handles_labels()
    l2, lb2 = ax2.get_legend_handles_labels()
    ax1.legend(l1 + l2, lb1 + lb2, loc='upper center', ncol=2, fontsize=13,
               framealpha=0.95, edgecolor='black')

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"\n[OK] Figura salva: {output_file}")
    print(f"  - Overhead Paranoid: {rot_oh_vals[0]:.1f} kB")
    print(f"  - Overhead Relaxed:  {rot_oh_vals[-1]:.1f} kB")
    print(f"  - Ratio Paranoid/Relaxed: {rot_oh_vals[0] / rot_oh_vals[-1]:.1f}×")
    return output_file


def generate_table_detailed_phase_room_policy(df, output_dir):
    """
    Tabela 3 do artigo: overhead absoluto de BW e tempo por fase × sala × política.
    """
    print(f"\n{'-' * 80}")
    print("Gerando Tabela 3: Overhead detalhado (Fase × Sala × Política)")
    print(f"{'-' * 80}")

    output_file = output_dir / "tab_detailed_phase_room_policy.tex"
    room_types = ['DM', 'SmallGroup', 'MediumGroup', 'LargeChannel']
    room_labels = {'DM': 'DM (2)', 'SmallGroup': 'Small (7)',
                   'MediumGroup': 'Medium (25)', 'LargeChannel': 'Large (150)'}
    policies = ['Paranoid', 'PQ3', 'Balanced', 'Relaxed']
    intervals = {'Paranoid': 25, 'PQ3': 50, 'Balanced': 100, 'Relaxed': 250}

    rows = []
    for rt in room_types:
        for pol in policies:
            sub = df[(df['room_type'] == rt) & (df['rotation_policy'] == pol)]
            dc = sub[sub['crypto_mode'] == 'Classical']
            dh = sub[sub['crypto_mode'] == 'Hybrid']
            if len(dc) == 0 or len(dh) == 0:
                continue
            rows.append({
                'room_type': room_labels[rt], 'policy': pol,
                'policy_interval': intervals[pol],
                'agr_bw_oh': dh['bandwidth_agreement'].median() - dc['bandwidth_agreement'].median(),
                'init_bw_oh': dh['bandwidth_initial_distribution'].median() - dc['bandwidth_initial_distribution'].median(),
                'rot_bw_oh': dh['bandwidth_rotation'].median() - dc['bandwidth_rotation'].median(),
                'setup_time_oh': dh['setup_time_ms'].median() - dc['setup_time_ms'].median(),
                'rot_time_oh': dh['rotation_time_ms'].median() - dc['rotation_time_ms'].median(),
            })

    def fmt_bw(val):
        if val < 1024:
            return f"{val:.0f}B"
        elif val < 1024 ** 2:
            return f"{val / 1024:.1f}KB"
        else:
            return f"{val / 1024 ** 2:.2f}MB"

    latex = [
        r"\begin{table}[!htbp]", r"\centering",
        r"\caption{Overhead Absoluto de Largura de Banda e Tempo por Fase, Sala e Política}",
        r"\label{tab:detailed_phase_room_policy}", r"\tiny",
        r"\begin{tabular}{ll|rr|rr}", r"\toprule",
        r"\multirow{2}{*}{\textbf{Sala}} & \multirow{2}{*}{\textbf{Política}} & "
        r"\multicolumn{2}{c|}{\textbf{Overhead de Largura de Banda}} & "
        r"\multicolumn{2}{c}{\textbf{Overhead de Tempo}} \\",
        r" & & \textbf{Setup} & \textbf{Rotação} & \textbf{Setup} & \textbf{Rotação} \\",
        r"\midrule",
    ]

    current_room = None
    for r in rows:
        room = r['room_type']
        if current_room is not None and current_room != room:
            latex.append(r"\midrule")
        current_room = room
        setup_bw = r['agr_bw_oh'] + r['init_bw_oh']
        latex.append(
            f"{room:15s} & {r['policy']:8s} ({r['policy_interval']:>3d}) & "
            f"{fmt_bw(setup_bw):>8s} & {fmt_bw(r['rot_bw_oh']):>8s} & "
            f"{r['setup_time_oh']:>6.2f}ms & {r['rot_time_oh']:>6.2f}ms \\\\"
        )

    latex += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        f.write('\n'.join(latex))

    print(f"[OK] Tabela salva: {output_file}")
    return output_file


# =============================================================================
# Main
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print("Uso: python scripts/analyze.py <csv_file>")
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    if not csv_path.exists():
        print(f"ERRO: Arquivo não encontrado: {csv_path}")
        sys.exit(1)

    output_dir = Path("tables_and_plots")

    print("=" * 80)
    print("ANÁLISE PAREADA E GERAÇÃO DE ARTEFATOS — SBRC 2026")
    print("=" * 80)
    print(f"\nArquivo: {csv_path}")
    print(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Carregar CSV
    df = pd.read_csv(csv_path)
    print(f"\nDimensões: {df.shape[0]} linhas × {df.shape[1]} colunas")

    # ── Parte 1: Análise estatística ──────────────────────────────────────
    print("\n" + "█" * 80)
    print("█  PARTE 1: ANÁLISE ESTATÍSTICA PAREADA")
    print("█" * 80)

    results_bw = analyze_bandwidth_by_phase(df)
    results_comp = analyze_pqc_components(df)
    results_rot = analyze_rotation_metrics(df)

    results_time = None
    correlations = None
    if 'setup_time_ms' in df.columns and 'rotation_time_ms' in df.columns:
        results_time = analyze_time_by_phase(df)
        correlations = analyze_bandwidth_time_correlation(df, results_bw, results_time)

    generate_summary(results_bw, results_comp, results_rot, results_time, correlations)

    # CSV estruturado
    print("\n" + "=" * 80)
    print("GERANDO CSV ESTRUTURADO")
    print("=" * 80)
    save_paired_analysis_csv(results_bw, csv_path)

    # ── Parte 2: Artefatos do artigo ─────────────────────────────────────
    print("\n" + "█" * 80)
    print("█  PARTE 2: GERAÇÃO DE ARTEFATOS DO ARTIGO")
    print("█" * 80)

    generate_figure_overhead_bw_vs_time(df, output_dir)
    generate_figure_policy_tradeoff(df, output_dir)
    generate_table_detailed_phase_room_policy(df, output_dir)

    # ── Resumo final ─────────────────────────────────────────────────────
    print(f"\n{'=' * 80}")
    print("[OK] ANÁLISE E ARTEFATOS GERADOS COM SUCESSO!")
    print(f"{'=' * 80}")
    print(f"\nArquivos gerados:")
    print(f"  Análise:")
    print(f"    • {csv_path.name.replace('.csv', '.paired_analysis.csv')}")
    print(f"  Figuras:")
    print(f"    • {output_dir}/fig_overhead_comparison_bandwidth_time.png  (Figura 3)")
    print(f"    • {output_dir}/fig_policy_tradeoff_smallgroup.png          (Figura 4)")
    print(f"  Tabelas:")
    print(f"    • {output_dir}/tab_detailed_phase_room_policy.tex          (Tabela 3)")
    print(f"\nNota: tab_bandwidth_primitives_compact.tex (Tabela 4) é mantida")
    print(f"manualmente em SBRC_2026_Matrix_PQC/tables/.")


if __name__ == "__main__":
    main()
