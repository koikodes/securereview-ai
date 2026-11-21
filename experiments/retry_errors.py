"""
Reruns only the samples that ended as Error for one tool in one run, and updates those rows.
A retry is a real second analysis, so a sample that still fails stays Error and is reported.
Usage: SECUREREVIEW_REAL=1 SEMGREP_TIMEOUT=180 python3 experiments/retry_errors.py <run_id> static_baseline|ai_reviewer
"""
import os, sys, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scoring.metrics import classify
from data.load_dataset import DB_PATH
from adapters import static_baseline_adapter as S, ai_reviewer_adapter as A

run_id, tool = sys.argv[1], sys.argv[2]
fn = {"static_baseline": S.run_static_baseline_real, "ai_reviewer": A.run_ai_reviewer_real}[tool]
conn = sqlite3.connect(DB_PATH)
rows = conn.execute("""SELECT r.sample_id, s.file_path, s.ground_truth, r.raw_output FROM results r
                       JOIN samples s USING(sample_id) WHERE r.run_id=? AND r.tool=? AND r.flagged='Error'""", (run_id, tool)).fetchall()
print(f"Retrying {len(rows)} errored samples for {tool} in run {run_id}")
fixed = 0
for i, (sid, path, gt, old) in enumerate(rows, 1):
    flag, raw = fn(path)
    if flag != "Error":
        fixed += 1
        conn.execute("UPDATE results SET flagged=?, classification=?, raw_output=? WHERE run_id=? AND tool=? AND sample_id=?",
                     (flag, classify(gt, flag), raw, run_id, tool, sid))
        conn.commit()
    print(f"  {i}/{len(rows)} {sid}: {flag}" + ("" if flag != "Error" else f" ({raw[:60]})"))
print(f"Fixed {fixed}, still Error {len(rows) - fixed}")
