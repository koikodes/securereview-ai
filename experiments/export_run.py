"""
Exports one run for analysis: per sample results with the rules that fired, and an environment record.
Usage: python3 experiments/export_run.py <run_id>
Writes experiments/per_sample_<run_id>.csv and experiments/run_record_<run_id>.json
"""
import os, sys, json, csv, sqlite3, platform, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.load_dataset import DB_PATH

run_id = sys.argv[1]
conn = sqlite3.connect(DB_PATH)
def sh(cmd):
    try: return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception: return ""

samples = conn.execute("SELECT sample_id, cwe_category, ground_truth FROM samples ORDER BY sample_id").fetchall()
res = {}
for sid, tool, flag, cls, raw in conn.execute("SELECT sample_id, tool, flagged, classification, raw_output FROM results WHERE run_id=?", (run_id,)):
    ids = ""
    try:
        o = json.loads(raw)
        if tool == "static_baseline": ids = ";".join(sorted({x["check_id"].split(".")[-1] for x in o.get("results", [])}))
        else: ids = ";".join(sorted({x.get("ruleId", "") for x in o["runs"][0]["results"]}))
    except Exception:
        ids = ""
    res[(sid, tool)] = (flag, cls, ids)
out = f"experiments/per_sample_{run_id}.csv"
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sample_id", "cwe_category", "ground_truth", "snyk_flag", "snyk_class", "snyk_rules", "semgrep_flag", "semgrep_class", "semgrep_rules"])
    for sid, cat, gt in samples:
        a = res.get((sid, "ai_reviewer"), ("", "", "")); s = res.get((sid, "static_baseline"), ("", "", ""))
        w.writerow([sid, cat, gt, *a, *s])
run = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
cols = [d[0] for d in conn.execute("SELECT * FROM runs LIMIT 0").description]
rules_dir = os.environ.get("SEMGREP_CONFIG", "")
rec = {
  "run": dict(zip(cols, run)) if run else None,
  "exported_utc": sh("date -u +%Y-%m-%dT%H:%M:%SZ"),
  "snyk_version": sh("snyk --version"), "semgrep_version": sh("semgrep --version --disable-version-check 2>/dev/null | tail -1"),
  "semgrep_config": rules_dir,
  "semgrep_rules_commit": sh(f"git -C '{os.path.dirname(rules_dir.rstrip('/'))}' rev-parse --short HEAD") if rules_dir else "",
  "benchmark_commit": sh("git -C ../BenchmarkJava rev-parse --short HEAD"),
  "semgrep_timeout_seconds": os.environ.get("SEMGREP_TIMEOUT", "not set when exported, see the note below"),
  "python": platform.python_version(), "os": platform.platform(), "machine": platform.machine(),
  "hardware": sh("sysctl -n machdep.cpu.brand_string 2>/dev/null; sysctl -n hw.memsize 2>/dev/null | awk '{printf \"%.0f GB RAM\", $1/1073741824}'"),
  "note": "Samples that timed out on Semgrep in the first pass were rerun once with a longer timeout using experiments/retry_errors.py",
}
json.dump(rec, open(f"experiments/run_record_{run_id}.json", "w"), indent=2)
print(f"Wrote {out} and experiments/run_record_{run_id}.json"); print(json.dumps(rec, indent=2))
