# Experiment record, Semgrep arm

Run id sg-511f82, 20 November 2026 UTC, 272 OWASP Benchmark v1.2 samples (17 vulnerable and 17 clean per category, seed 42).

Files
- run_metadata.json: tool version, ruleset commit, Benchmark commit, hardware, settings
- semgrep_confusion.csv: TP, FP, TN, FN, precision, recall, F1, FPR and Wilson 95 percent intervals, overall and per CWE
- semgrep_metrics.json: the same data with full precision
- semgrep_per_sample.csv: every sample with ground truth, flag, classification and the rules that fired

Reproduce
1. git clone https://github.com/OWASP-Benchmark/BenchmarkJava (commit 10dfcc5) and https://github.com/semgrep/semgrep-rules (commit a5ad171)
2. pip install semgrep   # the two-tool run used 1.136.0 (see run_record_d469d750.json)
3. python3 data/prepare_owasp_samples.py <BenchmarkJava> --per-category 34
4. python3 -c "from data.load_dataset import load_from_metadata_csv; load_from_metadata_csv('data/owasp_metadata.csv')"
5. SEMGREP_CONFIG=<semgrep-rules>/java python3 experiments/run_static_experiment.py
6. python3 experiments/analyze.py <run_id>

This is the earlier Semgrep-only run. The two-tool run (Snyk Code and Semgrep, run d469d750) is recorded in per_sample_d469d750.csv, run_record_d469d750.json, comparison.json and comparison_confusion.csv. Each tool was run once; no generative LLM was evaluated.
Tests: python3 -m unittest tests.test_regressions tests.test_stats
