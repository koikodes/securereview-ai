"""
pipeline/orchestrator.py

The piece that ties everything together. Loops through every sample in the
database, runs it through both adapters, and stores the results. This is the
only module that needs to know about both adapters — if a tool gets swapped
out later, only its one adapter file needs to change, not this one.

Usage:
    python pipeline/orchestrator.py            # full run, all loaded samples
    python pipeline/orchestrator.py --pilot    # pilot run, first 15 samples only
"""

import sqlite3
import sys
import os
import uuid
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters.ai_reviewer_adapter import run_ai_reviewer, TOOL_NAME as AI_TOOL_NAME
from adapters.static_baseline_adapter import run_static_baseline, TOOL_NAME as STATIC_TOOL_NAME
from data.load_dataset import DB_PATH, init_db
from scoring.metrics import classify


def run_pipeline(db_path=DB_PATH, pilot=False, pilot_size=15):
    conn = init_db(db_path)
    cur = conn.cursor()

    cur.execute("SELECT sample_id, file_path, cwe_category, ground_truth FROM samples")
    samples = cur.fetchall()

    if not samples:
        print("No samples loaded. Run data/load_dataset.py first.")
        return None

    if pilot:
        samples = samples[:pilot_size]

    run_id = str(uuid.uuid4())[:8]
    mode = "pilot" if pilot else "full"
    started_at = datetime.now(timezone.utc).isoformat()

    print(f"Starting {mode} run {run_id}: {len(samples)} samples")
    print(f"  AI reviewer:      {AI_TOOL_NAME}")
    print(f"  Static baseline:  {STATIC_TOOL_NAME}")

    error_count = 0
    for i, (sample_id, file_path, cwe_category, ground_truth) in enumerate(samples, 1):
        # AI reviewer
        ai_flag, ai_raw = run_ai_reviewer(file_path)
        ai_class = classify(ground_truth, ai_flag)
        cur.execute(
            "INSERT OR REPLACE INTO results (sample_id, tool, flagged, classification, raw_output, run_id) "
            "VALUES (?, 'ai_reviewer', ?, ?, ?, ?)",
            (sample_id, ai_flag, ai_class, ai_raw, run_id),
        )

        # Static baseline
        static_flag, static_raw = run_static_baseline(file_path)
        static_class = classify(ground_truth, static_flag)
        cur.execute(
            "INSERT OR REPLACE INTO results (sample_id, tool, flagged, classification, raw_output, run_id) "
            "VALUES (?, 'static_baseline', ?, ?, ?, ?)",
            (sample_id, static_flag, static_class, static_raw, run_id),
        )

        if ai_flag == "Error" or static_flag == "Error":
            error_count += 1

        if i % max(1, len(samples) // 10) == 0 or i == len(samples):
            print(f"  Processed {i}/{len(samples)} samples ({error_count} errors so far)")

    cur.execute(
        "INSERT INTO runs (run_id, started_at, ai_tool_name, static_tool_name, mode, sample_count) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, started_at, AI_TOOL_NAME, STATIC_TOOL_NAME, mode, len(samples)),
    )
    conn.commit()
    conn.close()

    print(f"\nRun {run_id} complete. {len(samples)} samples processed, {error_count} had errors on at least one tool.")
    return run_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", action="store_true", help="Run a 15-sample pilot instead of the full set")
    args = parser.parse_args()
    run_pipeline(pilot=args.pilot)
