# Constant-Time Cryptographic Execution Verifier & Timing Leakage Analyzer

> **Domain:** Applied Cryptography & Microarchitectural Side-Channel Security  
> **Reference Guidelines & Standards:** NIST SP 800-140C / FIPS 140-3, ISO/IEC 17825 (Side-Channel Analysis), NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), Dudect TVLA Criteria

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![Security Standards](https://img.shields.io/badge/Security-NIST_FIPS_140--3-green.svg)
![TVLA Engine](https://img.shields.io/badge/TVLA-Dudect_Welch's_t--test-orange.svg)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)

</div>

---

## 📖 What It Does

The **Constant-Time Cryptographic Execution Verifier** evaluates cryptographic routines, assembly implementations, and high-level source code to verify immunity against microarchitectural timing side-channel attacks. 

In non-constant-time cryptographic software, variable execution latency leaks secret keys, plaintexts, and sensitive intermediate values to unprivileged local or remote adversaries. This verifier integrates dynamic statistical timing leakage assessment (Dudect / TVLA methodology via Welch's two-sample t-test) with static AST vulnerability scanning for secret-dependent branch conditions, memory lookup indexing (cache-timing/Flush+Reload/Prime+Probe), early-exit string comparisons, and variable-latency arithmetic operations.

### Key Microarchitectural Hazard Models Analyzed

```
+-------------------------------------------------------------------------------+
|                       MICROARCHITECTURAL TIMING HAZARDS                      |
+-------------------------------------------------------------------------------+
| 1. Secret-Dependent Branching:                                                |
|    if (secret_key[i] == guess[i]) ...                                         |
|    -> Branch predictor state and pipeline execution depth leak secret bits    |
|                                                                               |
| 2. Secret-Dependent Memory Indexing:                                          |
|    state = SBOX[secret_byte ^ round_key];                                     |
|    -> CPU L1/L2 cache line hits vs. misses leak lookup indices (Cache Attacks)|
|                                                                               |
| 3. Early-Exit Loop Comparisons:                                               |
|    for b1, b2 in zip(tag, expected): if b1 != b2: return False                |
|    -> Execution duration proportional to matching byte prefix length          |
|                                                                               |
| 4. Variable-Latency Hardware Arithmetic:                                      |
|    quotient = secret_scalar % curve_order;                                    |
|    -> Hardware division / modulo cycles vary with operand bit length          |
+-------------------------------------------------------------------------------+
```

---

## ⚙️ Key Capabilities & Algorithmic Modules

### 🔬 Core Verification & Statistical Engines

- **`ConstantTimePrimitives`**: Branchless, constant-time bitwise cryptographic building blocks:
  - `ct_memcmp`: Constant-time buffer and authentication tag comparison without early exit.
  - `ct_select_int`: Branchless selection based on condition bitmask `(if_true & mask) | (if_false & ~mask)`.
  - `ct_cswap_int`: Branchless conditional register swap via bitwise XOR differences.
  - `ct_is_zero`: Constant-time zero-evaluator using two's complement sign-bit propagation.
  - `ct_min` / `ct_max`: Branchless signed/unsigned extrema selection.
- **`ConstantTimeVerifierEngine`**:
  - `run_welch_t_test`: Two-sample Welch's t-test engine with Welch–Satterthwaite degrees of freedom.
  - `compute_trace_statistics`: High-precision timing trace reduction (mean, variance, standard deviation, median, p95, p99).
  - `benchmark_comparison`: Interleaved Class 0 (fixed input) vs. Class 1 (random input) execution trials neutralizing thermal throttling and OS scheduler jitter.
  - `scan_source_code_ast`: Static AST scanner identifying secret-dependent branches, cache-indexed table lookups, early returns, and variable-latency division.
  - `verify_target`: Unified pipeline consolidating static findings and statistical TVLA verdicts.
- **`SystemSupervisor` & Domain Workers (`agents/`)**: Multi-worker consensus hierarchy auditing operational parameters, protocol conformance, and generating HMAC-SHA256 tamper-evident ledgers.

---

## 📐 Mathematical Formulation & Logic

### 1. Welch's Two-Sample t-Test (Dudect / TVLA)

Given two sets of execution timing measurements:
- Class 0 ($C_0$): Fixed inputs or constant ciphertexts ($N_0$ samples, sample mean $\bar{X}_0$, sample variance $s_0^2$)
- Class 1 ($C_1$): Random inputs or variable ciphertexts ($N_1$ samples, sample mean $\bar{X}_1$, sample variance $s_1^2$)

The Welch's $t$-statistic is defined as:

$$t = \frac{\bar{X}_0 - \bar{X}_1}{\sqrt{\frac{s_0^2}{N_0} + \frac{s_1^2}{N_1}}}$$

The effective degrees of freedom $\nu$ are calculated using the Welch–Satterthwaite equation:

$$\nu \approx \frac{\left( \frac{s_0^2}{N_0} + \frac{s_1^2}{N_1} \right)^2}{\frac{\left(s_0^2 / N_0\right)^2}{N_0 - 1} + \frac{\left(s_1^2 / N_1\right)^2}{N_1 - 1}}$$

### 2. Statistical Verdict Thresholds

| Absolute Score $\|t\|$ | Verdict | Statistical Interpretation | Security Action |
|:-----------------------|:--------|:---------------------------|:----------------|
| $\|t\| < 2.5$ | `PASS_CONSTANT_TIME` | Null hypothesis $H_0$ holds; no significant difference | Verified constant-time |
| $2.5 \le \|t\| \le 4.5$ | `SUSPICIOUS_MARGINAL` | Weak statistical deviation ($98.8\%$ to $99.9\%$ confidence) | Increase sample count ($N > 10^5$) |
| $\|t\| > 4.5$ | `FAIL_LEAKAGE_DETECTED` | Reject $H_0$ ($p < 10^{-5}$, $>99.999\%$ leakage confidence) | Critical side-channel vulnerability |

### 3. Branchless Bitwise Selection Logic

```text
mask = -condition_mask             // 1 -> 0xFFFFFFFF, 0 -> 0x00000000
result = (if_true & mask) | (if_false & ~mask)

ct_is_zero(x):
  return ((~x & (x - 1)) >> 31) & 1
```

---

## 💻 CLI Quickstart & Usage

The repository provides a command-line interface (`cli.py`) supporting single task audits, conversational configuration queries, cryptographic audit trail verification, and batch CSV processing.

### 1. Single Task Evaluation (`audit`)

Run a cryptographic audit for a target operation:

```bash
python cli.py audit --task-id TASK-2026-001 --target AES-GCM-TAG --primary 12.0 --secondary 4.0 --status NOMINAL
```

### 2. Batch Processing (`batch`)

Process a batch CSV dataset containing target identifiers, test metrics, and status flags:

```bash
# Process sample.csv and generate results
python cli.py batch -i sample.csv -o results.csv

# Alternative long flag syntax
python cli.py batch --input sample.csv --output results.csv
```

### 3. Query Supervisor Intelligence (`chat`)

Query system specifications and cryptographic standard guidelines:

```bash
python cli.py chat "Explain timing side-channel verification standards"
```

### 4. Verify Cryptographic Audit Trail (`verify-audit`)

Validate the HMAC-SHA256 cryptographic chain integrity across logged evaluation blocks:

```bash
python cli.py verify-audit
```

---

## 📊 Input Data Schema (`sample.csv`)

Batch input files use standard comma-separated tabular structure:

| Column Name | Type | Description | Example |
|:------------|:-----|:------------|:--------|
| `task_id` | `str` | Unique evaluation identifier | `TASK-001` |
| `target_identifier` | `str` | Target cryptographic primitive or key label | `TARGET-01` |
| `primary_metric` | `float` | Primary timing latency or statistical metric | `28.4` |
| `secondary_metric` | `float` | Secondary variance or dispersion index | `14.2` |
| `is_critical_flag` | `bool` | High-priority or emergency escalation indicator | `True` / `False` |
| `status_descriptor` | `str` | Preliminary status or anomaly descriptor | `NOMINAL`, `DISCORDANT` |

The batch command outputs the original records augmented with:
- `overall_urgency`: Consensus urgency classification (`ROUTINE`, `ELEVATED_RISK`, `CRITICAL_STAT_PANIC`).
- `integrity_status`: Verification status (`VALIDATED_OPTIMAL`, `DISCORDANT_ANOMALY`, `RECALIBRATION_REQUIRED`).
- `total_alerts`: Count of alerts emitted by domain workers.
- `audit_hash`: HMAC-SHA256 tamper-evident digital signature.

---

## 🛡️ Security Architecture & Standards

- **NIST FIPS 140-3 & SP 800-140C**: Conformance with physical and microarchitectural side-channel testing mandates.
- **ISO/IEC 17825**: Test methods for the mitigation of non-invasive attack classes on cryptographic modules.
- **Dudect Methodology**: TVLA through execution time sampling without requiring hardware power-measurement oscilloscopes.
- **Zero-PHI Interception**: Built-in pattern guards preventing accidental leak of sensitive records or credentials.
- **HMAC-SHA256 Audit Trail**: Hash-chained ledger ensuring non-repudiation of audit results.

---

## 🧪 Testing & Verification

Run the complete automated unit test suite:

```bash
python -m pytest -p no:zarr -v
```

Execute the batch CLI smoke verification:

```bash
python cli.py batch -i sample.csv -o out_smoke.csv
python -c "import os; assert os.path.exists('out_smoke.csv'); os.remove('out_smoke.csv')"
```

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

