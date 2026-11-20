"""
dashboard/app.py

Streamlit dashboard. Reads the latest pipeline run from the database and
displays overall and per-CWE-category metrics for the AI reviewer vs. the
static analysis baseline.

Run with:
    streamlit run dashboard/app.py
"""

import sys
import os
import sqlite3
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.load_dataset import DB_PATH, load_demo_samples
from pipeline.orchestrator import run_pipeline
from scoring.metrics import metrics_for_run

TOOL_LABELS = {"ai_reviewer": "AI Reviewer", "static_baseline": "Static Baseline"}

st.set_page_config(page_title="SecureReview AI", layout="wide")
st.title("SecureReview AI — Benchmarking Dashboard")


@st.cache_resource
def bootstrap_demo_run():
    """
    On a fresh deploy (e.g. Streamlit Community Cloud, which starts with no
    database), automatically load the demo dataset and run a pilot so the
    dashboard always has something to show instead of an empty page. Runs
    once per app session thanks to st.cache_resource.
    """
    load_demo_samples()
    run_pipeline(pilot=True)


if not os.path.exists(DB_PATH):
    with st.spinner("First run: loading demo data and running the pilot pipeline..."):
        bootstrap_demo_run()

conn = sqlite3.connect(DB_PATH)
runs = pd.read_sql_query("SELECT * FROM runs ORDER BY started_at DESC", conn)
conn.close()

if runs.empty:
    with st.spinner("Running demo pipeline..."):
        bootstrap_demo_run()
    conn = sqlite3.connect(DB_PATH)
    runs = pd.read_sql_query("SELECT * FROM runs ORDER BY started_at DESC", conn)
    conn.close()

if runs.empty:
    st.error("Could not generate demo data. Check the logs.")
    st.stop()

st.caption("Showing demo data generated automatically on first load. Load your real benchmark dataset and run the full pipeline to replace it — see the README.")

run_options = runs["run_id"] + " — " + runs["mode"] + " (" + runs["sample_count"].astype(str) + " samples, " + runs["started_at"].str.slice(0, 19) + ")"
selected = st.selectbox("Select a run", run_options)
selected_run_id = selected.split(" — ")[0]

run_row = runs[runs["run_id"] == selected_run_id].iloc[0]
st.caption(f"AI reviewer: {run_row['ai_tool_name']}  |  Static baseline: {run_row['static_tool_name']}  |  Mode: {run_row['mode']}")

metrics = metrics_for_run(run_id=selected_run_id)
if metrics is None:
    st.error("Could not load metrics for this run.")
    st.stop()

# ---------- Overall comparison ----------
st.header("Overall Results")

overall_rows = []
for tool_key, label in TOOL_LABELS.items():
    m = metrics[tool_key]["overall"]
    overall_rows.append({
        "Tool": label,
        "TP": m["TP"], "FP": m["FP"], "FN": m["FN"], "TN": m["TN"],
        "Recall": m["recall"], "False Positive Rate": m["false_positive_rate"],
        "Precision": m["precision"], "F1": m["f1"],
    })
overall_df = pd.DataFrame(overall_rows).set_index("Tool")

col1, col2 = st.columns([2, 1])
with col1:
    st.dataframe(
        overall_df.style.format({
            "Recall": "{:.1%}", "False Positive Rate": "{:.1%}",
            "Precision": "{:.1%}", "F1": "{:.2f}",
        }, na_rep="N/A"),
        use_container_width=True,
    )
with col2:
    chart_df = overall_df[["Recall", "False Positive Rate", "Precision"]].reset_index().melt(
        id_vars="Tool", var_name="Metric", value_name="Value"
    )
    st.bar_chart(chart_df, x="Metric", y="Value", color="Tool", stack=False, use_container_width=True)

# ---------- By CWE category ----------
st.header("Results by CWE Category")

all_categories = sorted(set(metrics["ai_reviewer"]["by_category"]) | set(metrics["static_baseline"]["by_category"]))
if not all_categories:
    st.info("No scored samples in this run yet.")
else:
    metric_choice = st.radio("Metric", ["Recall", "False Positive Rate", "Precision", "F1"], horizontal=True)
    metric_key = {"Recall": "recall", "False Positive Rate": "false_positive_rate", "Precision": "precision", "F1": "f1"}[metric_choice]

    rows = []
    for cat in all_categories:
        for tool_key, label in TOOL_LABELS.items():
            cat_metrics = metrics[tool_key]["by_category"].get(cat)
            value = cat_metrics[metric_key] if cat_metrics else None
            rows.append({"CWE Category": cat, "Tool": label, metric_choice: value})
    by_cat_df = pd.DataFrame(rows)

    pivot = by_cat_df.pivot(index="CWE Category", columns="Tool", values=metric_choice)
    st.bar_chart(pivot, stack=False, use_container_width=True)
    st.dataframe(
        pivot.style.format("{:.1%}" if metric_choice != "F1" else "{:.2f}", na_rep="N/A"),
        use_container_width=True,
    )

# ---------- Export ----------
st.header("Export")
conn = sqlite3.connect(DB_PATH)
export_df = pd.read_sql_query(
    """
    SELECT s.sample_id, s.cwe_category, s.ground_truth,
           r.tool, r.flagged, r.classification
    FROM results r
    JOIN samples s ON r.sample_id = s.sample_id
    WHERE r.run_id = ?
    ORDER BY s.sample_id, r.tool
    """,
    conn, params=(selected_run_id,),
)
conn.close()

st.download_button(
    "Download sample-level results as CSV",
    export_df.to_csv(index=False),
    file_name=f"securereview_results_{selected_run_id}.csv",
    mime="text/csv",
)
st.dataframe(export_df, use_container_width=True, height=300)
