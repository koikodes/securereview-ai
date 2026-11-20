"""
Compares the two tools of one orchestrator run: confusion data, metrics, Wilson 95% intervals,
and the exact McNemar test on per-sample correctness.
Usage: python3 experiments/compare.py [run_id]     (default: latest full run)
Writes experiments/comparison.json and experiments/comparison_confusion.csv
"""
import os, sys, json, csv, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scoring.metrics import calculate_metrics
from scoring.stats import wilson_ci, mcnemar_exact, paired_correctness
from data.load_dataset import DB_PATH

conn = sqlite3.connect(DB_PATH)
run_id = sys.argv[1] if len(sys.argv) > 1 else conn.execute(
    "SELECT run_id FROM runs WHERE mode='full' ORDER BY started_at DESC LIMIT 1").fetchone()[0]
rows = conn.execute("""SELECT r.tool, r.sample_id, r.classification, s.cwe_category
                       FROM results r JOIN samples s USING(sample_id) WHERE r.run_id=?""", (run_id,)).fetchall()
out = {"run_id": run_id, "tools": {}}
per_tool = {}
for tool in ("ai_reviewer", "static_baseline"):
    tr = [r for r in rows if r[0] == tool]
    per_tool[tool] = {r[1]: r[2] for r in tr}
    def block(rs):
        cl = [r[2] for r in rs]; m = calculate_metrics(cl); m["Error"] = cl.count("Error")
        m["recall_ci"] = wilson_ci(m["TP"], m["TP"] + m["FN"]); m["precision_ci"] = wilson_ci(m["TP"], m["TP"] + m["FP"])
        return m
    out["tools"][tool] = {"overall": block(tr), "by_category": {c: block([r for r in tr if r[3] == c]) for c in sorted({r[3] for r in tr})}}
b, c = paired_correctness(per_tool["ai_reviewer"], per_tool["static_baseline"])
out["mcnemar"] = {"ai_right_static_wrong": b, "static_right_ai_wrong": c, "p_value_exact_two_sided": mcnemar_exact(b, c)}
json.dump(out, open("experiments/comparison.json", "w"), indent=2)
with open("experiments/comparison_confusion.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["tool", "scope", "TP", "FP", "TN", "FN", "Error", "precision", "recall", "F1", "FPR"])
    for tool, d in out["tools"].items():
        for scope, m in [("OVERALL", d["overall"])] + list(d["by_category"].items()):
            r4 = lambda x: "" if x is None else round(x, 4)
            w.writerow([tool, scope, m["TP"], m["FP"], m["TN"], m["FN"], m["Error"], r4(m["precision"]), r4(m["recall"]), r4(m["f1"]), r4(m["false_positive_rate"])])
for tool, d in out["tools"].items():
    o = d["overall"]; print(tool, {k: (round(v, 3) if isinstance(v, float) else v) for k, v in o.items() if k not in ("recall_ci", "precision_ci")})
print("McNemar:", out["mcnemar"])
