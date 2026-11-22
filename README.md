# SecureReview AI

SecureReview AI is a benchmarking pipeline. It runs OWASP Benchmark Java samples through an AI-assisted code reviewer (Snyk Code) and a static analysis baseline (Semgrep), scores both against known ground truth, and shows recall, precision, false positive rate and F1 on a Streamlit dashboard, with confidence intervals and a paired significance test.

Course: CSC 380, Norfolk State University. Team: Group 11.
Repository: https://github.com/koikodes/securereview-ai

Pipeline: Benchmark dataset -> AI reviewer -> Static baseline -> Ground truth comparison -> Metrics engine -> Dashboard and reports.

## Team (Group 11)

| Member | Contribution |
|---|---|
| Hermajesty Williamson | Designed and built the system (loader, orchestrator, scoring and statistics, dashboard), integrated and ran the real tools, tests, documentation |
| Alston Williams | Feedback and project architecture |
| Jabari Staton | Feedback and project architecture |

See the final report for the full contribution summary.

## Major features

- Loads benchmark samples with ground truth from a metadata CSV (validated: labels, paths, duplicates) or a built-in demo set.
- 8 CWE categories: SQL Injection (89), Command Injection (78), Path Traversal (22), XSS (79), Weak Cryptography (327), Weak Hashing (328), Weak Randomness (330), Trust Boundary Violation (501).
- Runs every sample through both tools. A tool failure or timeout is recorded as `Error` and the run continues.
- Classifies each result TP, FP, FN, TN or Error; computes recall, FPR, precision, F1 overall and per category.
- Wilson 95% confidence intervals and an exact McNemar test comparing the two tools.
- SQLite storage of every run; read-only dashboard with charts and CSV export.
- Mock mode (default) so everything runs with no external tools.

## Requirements

- Python 3.9 or newer (developed on 3.9.6; also tested on 3.13), pip, git
- Demo mode needs only `requirements.txt` (streamlit, pandas, plotly)
- Real mode additionally needs: Snyk CLI with a Snyk account (`snyk auth`), Semgrep, and the OWASP BenchmarkJava source

## Setup

```bash
git clone https://github.com/koikodes/securereview-ai.git
cd securereview-ai
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
python3 -m pip install -r requirements.txt
```

The database (`securereview.db`) is created automatically. `Database_Scripts/schema.sql` shows the schema.

## Run in demo mode (no external tools)

```bash
python3 data/load_dataset.py             # loads 16 synthetic demo samples
python3 pipeline/orchestrator.py --pilot # mock tools, 15 samples
python3 -m streamlit run dashboard/app.py
```

Open http://localhost:8501. Demo runs are labeled as mock; their numbers are not real results.

A tiny example metadata file with four samples is in `data/test_data/`:

```bash
python3 -c "from data.load_dataset import load_from_metadata_csv; load_from_metadata_csv('data/test_data/example_metadata.csv')"
```

Sample files must be inside the `data/` folder (path restriction, SPR-10).

## Run the real experiment

1. Get the data and rules (commits used in the study):
   - BenchmarkJava at commit 10dfcc5: https://github.com/OWASP-Benchmark/BenchmarkJava
   - Semgrep rules at commit a5ad171: https://github.com/semgrep/semgrep-rules
2. Install and sign in: `pip install semgrep`, install the Snyk CLI, then `snyk auth`. Check `snyk --version` and `semgrep --version` work in the same terminal.
3. Prepare 272 balanced samples (34 per category, seed 42) and load them:
   ```bash
   python3 data/prepare_owasp_samples.py /path/to/BenchmarkJava --per-category 34
   python3 -c "from data.load_dataset import load_from_metadata_csv; load_from_metadata_csv('data/owasp_metadata.csv')"
   ```
4. Run both real tools:
   ```bash
   export SECUREREVIEW_REAL=1
   export SEMGREP_CONFIG=/path/to/semgrep-rules/java
   export SEMGREP_TIMEOUT=180
   python3 pipeline/orchestrator.py --pilot   # try 15 samples first
   python3 pipeline/orchestrator.py           # full run, prints a run id
   ```
5. If some samples ended as `Error` (for example timeouts), retry only those:
   ```bash
   python3 experiments/retry_errors.py <run_id> static_baseline
   python3 experiments/retry_errors.py <run_id> ai_reviewer
   ```
6. Compare and export:
   ```bash
   python3 experiments/compare.py <run_id>
   python3 experiments/export_run.py <run_id>
   ```
7. View results: `python3 -m streamlit run dashboard/app.py`

Configuration variables are listed in `.env.example`. Never commit a Snyk token or any credential.

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

20 tests (19 run as root on Linux; one file-permission test is skipped when run as root).

## Real run results (20 Nov 2026)

Run d469d750, 272 samples, 0 errors on both tools after retrying 25 Semgrep timeouts. Each tool was run once.

| Tool | Recall | Precision | F1 | FPR |
|---|---|---|---|---|
| Snyk Code 1.1309.0 | 0.941 | 0.650 | 0.769 | 0.507 |
| Semgrep 1.136.0 | 0.904 | 0.680 | 0.776 | 0.426 |

The overall difference is not significant (McNemar p = 0.57). By category, Snyk is better on CWE-22, 79, 89 and Semgrep is better on CWE-327 and 330. Two generic Snyk rules (ServerInformationExposure, NoHardcodedCredentials) are unrelated to the benchmark category and inflate its false positives; a post hoc scoring without them is reported in the paper and report, labeled post hoc. Per-sample data: `experiments/per_sample_d469d750.csv`; environment record: `experiments/run_record_d469d750.json`.

## Project structure

```
adapters/            one adapter per tool (real and mock)
pipeline/            orchestrator
scoring/             classification, metrics, statistics
dashboard/           Streamlit dashboard
data/                loader, OWASP sample preparation, test_data/
Database_Scripts/    schema.sql
experiments/         compare, export, retry scripts and the recorded run
tests/               unit and regression tests
.env.example         configuration example
```

## Known limitations

- Snyk Code is an AI-assisted analyzer, not a prompt-driven LLM. No generative LLM was evaluated.
- OWASP Benchmark is synthetic, Java only, and may overstate real-world performance. Each tool was run once.
- Scoring counts any finding as a flag, not only findings matching the sample's CWE.
- Snyk Code uploads code to Snyk's cloud; do not scan private code without permission.
- No login: the dashboard is read-only and meant for local use. Not tested on Windows.
- Open minor issues BUG-06, 08 and 09 (dashboard first-load write, adding a third tool needs more than one adapter, a deprecated Streamlit setting) do not affect scoring; see the report.
