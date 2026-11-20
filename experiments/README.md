# Experiment record, Semgrep arm

Run id sg-511f82, 20 November 2026 UTC, 272 OWASP Benchmark v1.2 samples (17 vulnerable and 17 clean per category, seed 42).

Files
- run_metadata.json: tool version, ruleset commit, Benchmark commit, hardware, settings
- semgrep_confusion.csv: TP, FP, TN, FN, precision, recall, F1, FPR and Wilson 95 percent intervals, overall and per CWE
- semgrep_metrics.json: the same data with full precision
- semgrep_per_sample.csv: every sample with ground truth, flag, classification and the rules that fired

Reproduce
1. git clone https://github.com/OWASP-Benchmark/BenchmarkJava (commit 10dfcc5) and https://github.com/semgrep/semgrep-rules (commit a5ad171)
2. pip install semgrep==1.186.0
3. python3 data/prepare_owasp_samples.py <BenchmarkJava> --per-category 34
4. python3 -c "from data.load_dataset import load_from_metadata_csv; load_from_metadata_csv('data/owasp_metadata.csv')"
5. SEMGREP_CONFIG=<semgrep-rules>/java python3 experiments/run_static_experiment.py
6. python3 experiments/analyze.py <run_id>

Not done: the AI reviewer arm (Snyk Code or a chosen LLM), so no McNemar test and no repeated AI runs.
Tests: python3 -m unittest tests.test_regressions tests.test_stats
