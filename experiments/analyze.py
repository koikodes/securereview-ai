"""Builds confusion data, metrics with Wilson CIs, and error-analysis samples for a run. Usage: analyze.py <run_id>"""
import os, sys, json, csv, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scoring.metrics import calculate_metrics
from scoring.stats import wilson_ci

run_id = sys.argv[1]
conn = sqlite3.connect("securereview.db")
rows = conn.execute("""SELECT s.sample_id, s.cwe_category, s.ground_truth, r.flagged, r.classification, r.raw_output
                       FROM results r JOIN samples s USING(sample_id) WHERE r.run_id=? AND r.tool='static_baseline'
                       ORDER BY s.sample_id""", (run_id,)).fetchall()
def block(rs):
    cl = [r[4] for r in rs]
    m = calculate_metrics(cl)
    m["Error"] = cl.count("Error"); m["N_scored"] = m["TP"]+m["FP"]+m["FN"]+m["TN"]
    m["recall_ci"] = wilson_ci(m["TP"], m["TP"]+m["FN"]); m["precision_ci"] = wilson_ci(m["TP"], m["TP"]+m["FP"])
    m["fpr_ci"] = wilson_ci(m["FP"], m["FP"]+m["TN"])
    return m
res = {"overall": block(rows), "by_category": {}}
for cat in sorted({r[1] for r in rows}):
    res["by_category"][cat] = block([r for r in rows if r[1] == cat])
json.dump(res, open("experiments/semgrep_metrics.json", "w"), indent=2)
with open("experiments/semgrep_confusion.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["scope","TP","FP","TN","FN","Error","precision","recall","F1","FPR","recall_CI_low","recall_CI_high","precision_CI_low","precision_CI_high"])
    for name, m in [("OVERALL", res["overall"])] + list(res["by_category"].items()):
        f4 = lambda x: "" if x is None else round(x, 4)
        w.writerow([name, m["TP"], m["FP"], m["TN"], m["FN"], m["Error"], f4(m["precision"]), f4(m["recall"]), f4(m["f1"]), f4(m["false_positive_rate"]),
                    f4(m["recall_ci"][0]), f4(m["recall_ci"][1]), f4(m["precision_ci"][0]), f4(m["precision_ci"][1])])
with open("experiments/semgrep_per_sample.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["sample_id","cwe_category","ground_truth","flagged","classification","rule_ids"])
    for sid, cat, gt, fl, cl, raw in rows:
        ids = ""
        try: ids = ";".join(sorted({x["check_id"].split(".")[-1] for x in json.loads(raw).get("results", [])}))
        except Exception: pass
        w.writerow([sid, cat, gt, fl, cl, ids])
print(json.dumps(res["overall"], indent=1)); print(open("experiments/semgrep_confusion.csv").read())
