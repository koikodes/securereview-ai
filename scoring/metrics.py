"""
scoring/metrics.py

Ground-Truth Comparison + Metrics Engine.

classify() turns one (ground_truth, flagged) pair into TP/FP/FN/TN/Error.
The rest of this file reads the results table and calculates recall,
false-positive rate, precision, and F1, overall and broken down by CWE
category, for each tool.
"""

import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.load_dataset import DB_PATH


def classify(ground_truth, flagged):
    """Classifies one tool result against ground truth."""
    if flagged == "Error":
        return "Error"
    if ground_truth == "Vulnerable" and flagged == "Y":
        return "TP"
    if ground_truth == "Vulnerable" and flagged == "N":
        return "FN"
    if ground_truth == "Clean" and flagged == "Y":
        return "FP"
    if ground_truth == "Clean" and flagged == "N":
        return "TN"
    return "Unscored"  # covers any unexpected ground_truth/flag combination


def _safe_div(numerator, denominator):
    return numerator / denominator if denominator else None


def calculate_metrics(classifications):
    """Takes a list of TP/FP/FN/TN strings and returns the standard metrics."""
    tp = classifications.count("TP")
    fp = classifications.count("FP")
    fn = classifications.count("FN")
    tn = classifications.count("TN")

    recall = _safe_div(tp, tp + fn)
    fpr = _safe_div(fp, fp + tn)
    precision = _safe_div(tp, tp + fp)
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * (precision * recall) / (precision + recall)

    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "recall": recall, "false_positive_rate": fpr,
        "precision": precision, "f1": f1,
    }


def get_latest_run_id(conn):
    row = conn.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
    return row[0] if row else None


def metrics_for_run(run_id=None, db_path=DB_PATH):
    """
    Returns a dict:
    {
        "ai_reviewer":      {"overall": {...}, "by_category": {category: {...}, ...}},
        "static_baseline":  {"overall": {...}, "by_category": {category: {...}, ...}},
        "run_id": ...
    }
    """
    conn = sqlite3.connect(db_path)
    if run_id is None:
        run_id = get_latest_run_id(conn)
    if run_id is None:
        conn.close()
        return None

    rows = conn.execute(
        """
        SELECT r.tool, r.classification, s.cwe_category
        FROM results r
        JOIN samples s ON r.sample_id = s.sample_id
        WHERE r.run_id = ? AND r.classification IN ('TP', 'FP', 'FN', 'TN')
        """,
        (run_id,),
    ).fetchall()
    conn.close()

    output = {"run_id": run_id}
    for tool in ("ai_reviewer", "static_baseline"):
        tool_rows = [(c, cat) for t, c, cat in rows if t == tool]
        overall = calculate_metrics([c for c, _ in tool_rows])

        by_category = {}
        categories = sorted(set(cat for _, cat in tool_rows))
        for cat in categories:
            cat_classes = [c for c, category in tool_rows if category == cat]
            by_category[cat] = calculate_metrics(cat_classes)

        output[tool] = {"overall": overall, "by_category": by_category}

    return output


if __name__ == "__main__":
    import json
    result = metrics_for_run()
    if result is None:
        print("No runs found. Run pipeline/orchestrator.py first.")
    else:
        print(json.dumps(result, indent=2))
