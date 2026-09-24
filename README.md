# Constant-Time Crypto Verifier

A small Python toolkit for screening timing traces and Python source code for potential data-dependent timing behavior.

## What it does

The repository contains two primary analyses:

- **Timing analysis:** computes descriptive statistics and Welch's two-sample *t* statistic for two classes of raw timing observations.
- **Static source scan:** parses Python source with `ast` and reports heuristic patterns such as secret-dependent branches, secret-indexed lookups, early exits in secret-related loops, and division/modulo involving secret-like identifiers.

The browser interface runs the same Python analysis module client-side with Pyodide. No backend is required for the web application.

## Important limitations

This project is a screening and educational tool, not a constant-time proof system or a cryptographic certification tool.

- A low absolute *t* statistic means that this particular sample did not show a difference at the configured threshold; it does **not** prove constant-time execution.
- The AST scanner is heuristic and Python-specific. It does not inspect compiler output, machine instructions, caches, branch predictors, or other microarchitectural state.
- CPython does not guarantee constant-time execution of integer arithmetic or control flow. `ConstantTimePrimitives.ct_memcmp` therefore delegates to `hmac.compare_digest`; the other bitwise helpers are retained for demonstration and correctness tests, not as a production cryptographic boundary.
- The commonly used `|t| > 4.5` screening threshold is treated as a heuristic. The code does not present it as a calculated confidence interval or universal p-value.

For serious side-channel evaluation, combine controlled measurements with dedicated tooling and review the generated native implementation where applicable.

## Browser use

Open the GitHub Pages application, wait for the **Python ready** indicator, then choose either:

1. **Timing test** — paste the two timing classes and run the Welch screen.
2. **Source scan** — paste Python source and inspect the reported heuristic findings.

The page has light and dark themes and is responsive. Input data remains in the browser. The page downloads the Pyodide runtime from jsDelivr and loads `constant_time_crypto_verifier.py` from the same GitHub Pages site.

## Python installation

```bash
python -m pip install .
```

Optional API dependencies:

```bash
python -m pip install ".[api]"
```

Development dependencies:

```bash
python -m pip install ".[api,dev]"
```

## CLI

Scan Python source:

```bash
constant-time-crypto-verifier scan implementation.py
```

Analyze a CSV containing `class0_ns` and `class1_ns` columns:

```bash
constant-time-crypto-verifier tvla timings.csv
```

Combine source and timing checks:

```bash
constant-time-crypto-verifier verify \
  --name example \
  --source implementation.py \
  --timings timings.csv
```

Add `--json` to the core analysis commands for structured output.

The older `audit`, `batch`, `chat`, `verify-audit`, and `serve` commands remain available for backward compatibility with the repository's threshold-worker interface.

## API

With the `api` extra installed:

```bash
constant-time-crypto-verifier serve
```

Core endpoints include:

- `POST /api/tvla`
- `POST /api/scan`
- `GET /health`

The legacy `/api/audit` and `/api/chat` endpoints are retained for compatibility.

## Development and verification

```bash
python -m compileall -q .
ruff check cli.py constant_time_crypto_verifier.py agents/base.py agents/api.py \
  agents/llm_factory.py agents/models.py agents/supervisor.py agents/workers.py
python -m pytest
python -m build
pip-audit --skip-editable
```

GitHub Actions runs the test matrix on Python 3.10-3.13, verifies the installed console command, builds the distribution, performs dependency auditing, and deploys the static browser interface to GitHub Pages from `master`.

## Technology

- Python standard library for the core timing/statistical and AST analysis
- Pydantic for the retained worker schemas
- FastAPI/Uvicorn as optional API dependencies
- Pyodide for in-browser Python execution
- Plain HTML, CSS, and JavaScript for the web interface

Modern versions of Chrome, Edge, Firefox, and Safari with WebAssembly support are expected to work. The browser interface requires network access to load Pyodide from jsDelivr.

## License

MIT. See [LICENSE](LICENSE).
