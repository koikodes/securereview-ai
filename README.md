# SecureReview AI

SecureReview AI is an automated benchmarking system. It runs benchmark code samples through an AI code review tool and a static analysis tool, compares both against known ground truth, and reports detection metrics on a dashboard.

Pipeline: Benchmark Dataset, AI Reviewer, Static Analysis Baseline, Ground Truth Comparison, Metrics Engine, Dashboard and Reports.

## Team (Group 11)

| Member | Responsibility |
|---|---|
| Hermajesty Williamson | Dataset loader, orchestrator, scoring and metrics, dashboard |
| Alston Williams | AI reviewer adapter (Snyk Code) |
| Jabari Staton | Static analysis baseline adapter (Semgrep) |

## Major features

- Loads benchmark samples with ground truth labels from a demo set or from OWASP Benchmark.
- Covers 8 CWE categories: SQL Injection, Command Injection, Path Traversal, XSS, Weak Cryptography, Weak Hashing, Weak Randomness and Trust Boundary Violation.
- Runs every sample through an AI reviewer adapter and a static baseline adapter.
- Classifies each result as TP, FP, FN, TN or Error.
- Calculates recall, false positive rate, precision and F1, overall and per category.
- Stores every run in SQLite so results can be reproduced.
- Shows results in a Streamlit dashboard with charts and CSV export.

## Technologies used

Python 3, SQLite, Streamlit, pandas, plotly, Snyk Code CLI, Semgrep, OWASP BenchmarkJava dataset.

## Setup

```bash
python3 -m pip install -r requirements.txt
```

## How to run (demo mode, no real tools needed)

```bash
python3 data/load_dataset.py
python3 pipeline/orchestrator.py --pilot
python3 -m streamlit run dashboard/app.py
```

## Using real OWASP samples

1. Download BenchmarkJava from github.com/OWASP-Benchmark/BenchmarkJava and unzip it.
2. Prepare a balanced sample:
   ```bash
   python3 data/prepare_owasp_samples.py /path/to/BenchmarkJava-master --per-category 34
   ```
3. Load it:
   ```bash
   python3 -c "from data.load_dataset import load_from_metadata_csv; load_from_metadata_csv('data/owasp_metadata.csv')"
   ```
4. Run the pipeline and open the dashboard:
   ```bash
   python3 pipeline/orchestrator.py
   python3 -m streamlit run dashboard/app.py
   ```

## Using real tools

Install and sign in to Snyk Code and Semgrep, then set `USE_MOCK = False` in `adapters/ai_reviewer_adapter.py` and `adapters/static_baseline_adapter.py`. Never commit tool tokens to the repository.

## Project structure

```
data/        dataset loader and OWASP sample preparation
adapters/    one adapter per tool
pipeline/    orchestrator that runs every sample through both tools
scoring/     ground truth comparison and metrics engine
dashboard/   Streamlit dashboard
```

## Current project status

The full pipeline runs end to end in demo mode and on 272 real OWASP Benchmark samples with mock adapters. The dashboard works locally. Real tool mode for Snyk Code and Semgrep has not been tested yet.

## Known issues and limitations

- Mock adapters use simple patterns, so mock recall on real Java samples is low. Results are only meaningful once real tools are connected.
- In real mode, a tool that cannot read a file may return no findings, which is recorded as N instead of Error.
- The dataset loader does not yet restrict file paths to the sample folder.
- Semgrep with the auto ruleset needs internet access to download rules.
- A shareable dashboard link has not been deployed yet.
