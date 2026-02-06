# Vodozemac Wrapper PQC

**Uma Extensão Pós-Quântica Híbrida para o Protocolo Matrix: Avaliação Experimental e Impacto Sistêmico**

Este repositório contém o código-fonte referente ao artigo submetido ao Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (**SBRC 2026**).

## Resumo

A computação quântica ameaça a criptografia de mensageiros E2EE, impulsionando a adoção de criptografia pós-quântica (PQC). Este estudo avalia a integração híbrida do CRYSTALS-Kyber no protocolo Matrix, estendendo o acordo de chaves e o Double Ratchet. Testes experimentais demonstram que o principal gargalo é a largura de banda, com overhead de +548% no setup e +252% nas rotações de chaves, enquanto o impacto na CPU e na experiência do usuário é negligenciável (≈16ms a 100ms). O custo das rotações escala quadraticamente, indicando que políticas de segurança rígidas são ineficientes e demandam estratégias adaptativas para equilibrar segurança e consumo de rede.

## Estrutura do Código

```
vodozemac-wrapper-pqc/
├── src/
│   ├── core/                   # Primitivas criptográficas fundamentais
│   │   ├── crypto.rs           # Definições de algoritmos (KEM, DH, Signature)
│   │   ├── pqxdh.rs            # Protocolo PQXDH (X3DH + Kyber)
│   │   ├── double_ratchet_pqc.rs  # Double Ratchet híbrido
│   │   ├── providers/          # Implementações PQC e clássicas
│   │   └── mod.rs
│   │
│   ├── protocols/              # Protocolos de alto nível
│   │   ├── room.rs             # Salas Matrix (Olm + Megolm) com rotação
│   │   └── mod.rs
│   │
│   ├── demos/                  # Experimentos e benchmarks
│   │   ├── user_profile_benchmark.rs  # Benchmark principal (11 salas)
│   │   └── mod.rs
│   │
│   ├── tools/                  # Utilitários auxiliares
│   │   ├── workload.rs         # Geração de carga de trabalho
│   │   └── mod.rs
│   │
│   ├── utils/                  # Infraestrutura de suporte
│   │   ├── logging.rs          # Sistema de verbosidade (0-4)
│   │   └── mod.rs
│   │
│   ├── lib.rs                  # Biblioteca principal
│   └── main.rs                 # Interface CLI
│
├── scripts/
│   ├── analyze_paired.py       # Análise estatística pareada
│   └── requirements.txt        # Dependências Python
│
├── results/                    # Saída dos experimentos (CSVs)
├── Cargo.toml                  # Configuração do pacote
└── README.md
```

## Compilação e Execução

### Requisitos

- **Rust**: 1.70+ (edition 2021)
- **Python**: 3.8+ com pandas, numpy, scipy, matplotlib (para análise)
- **Sistema**: Linux/macOS recomendado (testado em Ubuntu 20.04+)

### Compilar

```bash
# Compilação otimizada (release)
cargo build --release

# Binário gerado em: target/release/vodozemac-wrapper-pqc
```

### Executar Benchmark

#### Teste Rápido (1 política, 5 repetições)

```bash
cargo run --release -- \
  --mode user-profile \
  --repetitions 5 \
  --rotation-policy balanced \
  --verbosity 1
```

#### Benchmark Completo (4 políticas, 30 repetições)

```bash
time cargo run --release -- \
  --mode user-profile \
  --repetitions 30 \
  --all-rotation-policies \
  --verbosity 1
```

**Saída**: Arquivo CSV único em `results/resultados_experiment_<timestamp>.csv`

#### Política Específica

```bash
# Testar apenas política Paranoid (máxima segurança)
cargo run --release -- \
  --mode user-profile \
  --repetitions 30 \
  --rotation-policy paranoid \
  --verbosity 2

# Testar apenas política Relaxed (performance otimizada)
cargo run --release -- \
  --mode user-profile \
  --repetitions 30 \
  --rotation-policy relaxed \
  --verbosity 2
```

### Opções de Linha de Comando

```
--mode <MODE>                    Modo de operação [default: user-profile]
--repetitions <N>                Número de repetições pareadas [default: 5]
--all-rotation-policies          Testar TODAS as políticas (Paranoid, PQ3, Balanced, Relaxed)
--rotation-policy <POLICY>       Política específica: paranoid|pq3|balanced|relaxed
--verbosity <LEVEL>              Nível de verbosidade [default: 2]
                                   0 = Silent (sem saída)
                                   1 = Minimal (progresso básico)
                                   2 = Normal (informações importantes)
                                   3 = Verbose (detalhes de execução)
                                   4 = Debug (logs completos de rotação)
```

### Análise Estatística

```bash
# Análise pareada com testes estatísticos (Wilcoxon, intervalos de confiança)
python3 scripts/analyze_paired.py \
  results/resultados_experiment_<timestamp>.csv

```

**Saída da Análise**:
- Comparação Classical vs. Hybrid por componente (Agreement, Initial Distribution, Rotation)
- Testes de significância estatística (p-values)
- Intervalos de confiança (95%)
- Overhead PQC absoluto e relativo

## Experimentos

### Cenários de Benchmark

O benchmark `user-profile` simula um perfil de usuário Matrix realista com **11 salas**:

| Tipo de Sala       | Membros | Quantidade | Descrição                           |
|-------------------|---------|------------|-------------------------------------|
| DM (Direct)       | 2       | 3 salas    | Conversas 1-a-1                     |
| Small Group       | 5-10    | 4 salas    | Grupos pequenos (família, amigos)   |
| Medium Group      | 15-25   | 2 salas    | Grupos médios (equipes de trabalho) |
| Large Channel     | 50-100  | 2 salas    | Canais grandes (comunidades)        |

**Total**: 220 sessões Olm + 11 sessões Megolm

### Políticas de Rotação de Chaves

| Política  | Mensagens | Uso Recomendado                    |
|-----------|-----------|------------------------------------|
| Paranoid  | 25        | Máxima segurança (ambiente hostil) |
| PQ3       | 50        | Inspirado no Apple PQ3             |
| Balanced  | 100       | Padrão recomendado (balanceado)    |
| Relaxed   | 250       | Performance otimizada (IoT)        |

### Métricas Coletadas (56 colunas CSV)

#### Identificadores
- `batch_id`: Identificador do experimento
- `pair_id`: Par Classical-Hybrid (permite análise pareada)
- `repeat_id`: 0 = Classical, 1 = Hybrid

#### Hardware Profile
- `device_type`, `architecture`, `cpu_cores`, `cpu_freq_mhz`

#### Timing (ms)
- `setup_time_ms`: Tempo de configuração inicial
- `rotation_time_ms`: Tempo de rotações de chaves
- `encrypt_steady_state_ms`: Tempo de criptografia em estado estável

#### Bandwidth (bytes)
- **Agreement**: `bandwidth_agreement`, `bandwidth_agreement_pqc`
- **Initial Distribution**: `bandwidth_initial_distribution`, `bandwidth_initial_distribution_pqc`
- **Rotation**: `bandwidth_rotation`, `bandwidth_rotation_pqc`
- **Refinado**: 10 componentes detalhados (KEM, signatures, ratchets, etc.)

#### Ratchet Metrics
- `num_ratchet_advances`: Total de avanços de ratchet
- `num_asymmetric_advances`: Avanços assimétricos (custos maiores)
- `num_rotation_messages`: Mensagens enviadas durante rotações

#### Primitivas PQC (16 métricas)
- Contagens de operações: `kem_keygen_count`, `kem_encaps_count`, `kem_decaps_count`
- Tamanhos: `kem_pk_bytes`, `kem_ct_bytes`, `kem_ss_bytes`
- DH clássico: `dh_keygen_count`, `dh_exchange_count`
- Assinaturas: `sign_count`, `verify_count`

#### Primitivas PQC (16 métricas)
- Contagens de operações: `kem_keygen_count`, `kem_encaps_count`, `kem_decaps_count`
- Tamanhos: `kem_pk_bytes`, `kem_ct_bytes`, `kem_ss_bytes`
- DH clássico: `dh_keygen_count`, `dh_exchange_count`
- Assinaturas: `sign_count`, `verify_count`

### Formato de Dados

**Long/Tidy Format**: Cada linha representa uma sala em uma repetição específica.
- Permite análise pareada via `pair_id`
- `repeat_id=0` (Classical) é pareado com `repeat_id=1` (Hybrid)
- Ideal para testes estatísticos não-paramétricos (Wilcoxon signed-rank)

## Segurança

### Propriedades Criptográficas

- **Forward Secrecy**: Comprometimento de chaves antigas não afeta sessões futuras
- **Post-Compromise Security**: Recuperação automática após comprometimento
- **Break-in Recovery**: Double Ratchet restaura segurança após N mensagens
- **Cross-Signature Validation**: Binding criptográfico entre Ed25519 e Curve25519

### Algoritmos Utilizados

#### Pós-Quânticos
- **KEM**: Kyber-1024 (CRYSTALS-Kyber, NIST Level 5)
  - Chave pública: 1568 bytes
  - Ciphertext: 1568 bytes
  - Shared secret: 32 bytes

#### Clássicos (Backup)
- **DH**: X25519 (Curve25519 ECDH)
- **Assinatura**: Ed25519
- **KDF**: HKDF-SHA-256
- **Cifra Simétrica**: AES-256-CBC (Megolm)
- **MAC**: HMAC-SHA-256

## Reprodutibilidade

### Ambiente de Teste

```bash
# Sistema operacional
uname -a  # Linux 5.15+ recomendado

# Versão Rust
rustc --version  # rustc 1.70+

# Dependências Python
pip3 install pandas numpy scipy matplotlib seaborn

# Hardware recomendado
# CPU: 4+ cores
# RAM: 8+ GB
# Disco: 2+ GB livre
```

### Executar Experimento Completo

```bash
# 1. Limpar resultados anteriores
rm -rf results/*.csv

# 2. Executar benchmark completo (4 políticas × 30 repetições)
time cargo run --release -- \
  --mode user-profile \
  --repetitions 30 \
  --all-rotation-policies \
  --verbosity 1 \
  2>&1 | tee experiment.log

# 3. Verificar arquivo gerado
ls -lh results/resultados_experiment_*.csv

# 4. Análise estatística
python3 scripts/analyze_paired.py \
  results/resultados_experiment_*.csv \
  > analysis_report.txt

# 5. Revisar resultados
cat analysis_report.txt
```

## Citação

Se você utilizar este código em sua pesquisa, por favor cite este repositório.

## Licença


## Autores

- Marcos Dantas Ortiz (mdo@ufc.br)

## Links Úteis

- **Matrix Protocol**: https://matrix.org
- **Vodozemac**: https://github.com/matrix-org/vodozemac
- **CRYSTALS-Kyber**: https://pq-crystals.org/kyber/
- **NIST PQC**: https://csrc.nist.gov/projects/post-quantum-cryptography

## Suporte

Para questões sobre o código ou experimentos:
- Entre em contato: mdo@ufc.br

---


