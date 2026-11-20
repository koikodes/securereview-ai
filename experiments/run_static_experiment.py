"""
Runs the real Semgrep arm on the loaded 272 OWASP samples using the project's own adapter
(with the BUG-05 fix), stores results in securereview.db and writes run metadata to
experiments/run_metadata.json. Usage: SEMGREP_CONFIG=<rules dir> python3 experiments/run_static_experiment.py
"""
import os, sys, json, sqlite3, uuid, platform, subprocess, time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from adapters import static_baseline_adapter as S
from scoring.metrics import classify
from data.load_dataset import init_db, DB_PATH

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

conn = init_db(DB_PATH)
samples = conn.execute("SELECT sample_id, file_path, ground_truth FROM samples ORDER BY sample_id").fetchall()
run_id = "sg-" + str(uuid.uuid4())[:6]
t0 = time.time(); started = datetime.now(timezone.utc).isoformat()
def work(s):
    return s, S.run_static_baseline_real(s[1])
with ThreadPoolExecutor(max_workers=2) as ex:
    out = list(ex.map(work, samples))
for (sid, fp, gt), (flag, raw) in out:
    conn.execute("INSERT OR REPLACE INTO results (sample_id, tool, flagged, classification, raw_output, run_id) VALUES (?,?,?,?,?,?)",
                 (sid, "static_baseline", flag, classify(gt, flag), raw, run_id))
conn.execute("INSERT INTO runs (run_id, started_at, ai_tool_name, static_tool_name, mode, sample_count) VALUES (?,?,?,?,?,?)",
             (run_id, started, "NOT RUN", "Semgrep " + sh("semgrep --version"), "full-static-only", len(samples)))
conn.commit(); conn.close()
meta = {
  "run_id": run_id, "started_utc": started, "elapsed_seconds": round(time.time() - t0, 1),
  "samples": len(samples), "semgrep_version": sh("semgrep --version"),
  "semgrep_config": S.SEMGREP_CONFIG, "semgrep_rules_repo": "https://github.com/semgrep/semgrep-rules",
  "semgrep_rules_commit": sh("git -C %s rev-parse HEAD" % os.path.dirname(S.SEMGREP_CONFIG)),
  "semgrep_rule_count_loaded": 113, "flag_rule": "Y if Semgrep reports one or more findings in the file, N if scanned with zero findings, Error otherwise",
  "benchmark_repo": "https://github.com/OWASP-Benchmark/BenchmarkJava", "benchmark_commit": sh("git -C /home/claude/exp/bj rev-parse HEAD"),
  "sampling": "prepare_owasp_samples.py --per-category 34, seed 42, 17 vulnerable and 17 clean per category",
  "python": platform.python_version(), "os": platform.platform(), "machine": platform.machine(),
  "cpus": os.cpu_count(), "ram": sh("free -h | awk '/Mem/{print $2}'"), "workers": 2,
  "ai_reviewer": "NOT RUN: Snyk Code (api.snyk.io) is blocked from the sandbox and no authenticated token was available",
}
json.dump(meta, open("experiments/run_metadata.json", "w"), indent=2)
print(json.dumps(meta, indent=2))
