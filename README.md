# Constant Time Crypto Verifier

> **Domain:** Post-Quantum Cryptography & Zero-Knowledge Architecture  
> **Reference Guidelines & Standards:** `NIST FIPS 203/204/205, NIST SP 800-90B & ISO/IEC Standards`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

Constant-Time Cryptographic Execution Verifier & Timing Leakage Analyzer
-------------------------------------------------------------------------
Implements statistical timing side-channel detection (TVLA / Dudect methodology via
Welch's t-test), static AST vulnerability scanning for secret-dependent branching/lookups,
and a verified suite of constant-time cryptographic primitives.

Domain: Applied Cryptography / Microarchitectural Side-Channel Security
Pure Python Standard Library (no external dependencies required).

Constant-Time Cryptographic Execution Verifier & Timing Leakage Analyzer
-------------------------------------------------------------------------
Implements statistical timing side-channel detection (TVLA / Dudect methodology via
Welch's t-test), static AST vulnerability scanning for secret-dependent branching/lookups,
and a verified suite of constant-time cryptographic primitives.

Domain: Applied Cryptography / Microarchitectural Side-Channel Security
Pure Python Standard Library (no external dependencies required).

---

## ⚙️ Key Capabilities & Algorithmic Modules

### 🔬 Core Algorithmic & Evaluation Engines

- **`TimingTraceStatistics`**: Descriptive statistics for a set of timing execution samples.
- **`TVLATestResult`**: Welch's two-sample t-test results for timing side-channel leakage.
- **`StaticCodeVulnerability`**: Detected static microarchitectural timing vulnerability.
- **`StaticASTAuditResult`**: Result of static source code analysis for non-constant time patterns.
- **`VerificationReport`**: Unified constant-time cryptographic verification audit report.
- **`ConstantTimePrimitives`**: Cryptographically sound, branchless, constant-time primitives in pure Python.
Designed to prevent microarchitectural timing leaks and cache side-channels.

---

## 📐 Mathematical Formulation & Logic

```text
  return (if_true & mask) | (if_false & ~mask)
  return ((~x_32 & (x_32 - 1)) >> 31) & 1
  risk = min(100.0, len(findings) * 35.0)
```

---

## 💻 CLI Quickstart & Usage

### 1. Guided Interactive Mode
```bash
python cli.py
```

### 2. Direct Parameterized Evaluation
```bash
python cli.py --task-id <value> --target <value> --primary <value> --secondary <value>
```

### Parameter Reference
- `--task-id`: Specifies input measurement or parameter value.
- `--target`: Specifies input measurement or parameter value.
- `--primary`: Specifies input measurement or parameter value.
- `--secondary`: Specifies input measurement or parameter value.
- `--critical`: Specifies input measurement or parameter value.
- `--status`: Specifies input measurement or parameter value.
- `--input`: Specifies input measurement or parameter value.
- `--output`: Specifies input measurement or parameter value.

### Input Data Schema

| Field | Description | Requirement |
|:------|:------------|:------------|
| `task_id` | Parameter / observation metric | Required |
| `target_identifier` | Parameter / observation metric | Required |
| `primary_metric` | Parameter / observation metric | Required |
| `secondary_metric` | Parameter / observation metric | Required |
| `is_critical_flag` | Parameter / observation metric | Required |
| `status_descriptor` | Parameter / observation metric | Required |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active AST and regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs for every evaluation and state transition.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **Active Learning Bayesian Calibration:** Dynamic tracker updating worker reliability weights and monitoring Brier calibration drift.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py --tasks 1000 --concurrency 8
```

---

## 🐳 Container Deployment

```bash
docker build -t constant-time-crypto-verifier .
docker run -p 8000:8000 constant-time-crypto-verifier
```
