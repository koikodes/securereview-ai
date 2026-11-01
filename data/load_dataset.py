"""
data/load_dataset.py

Loads benchmark code samples into the shared SQLite database.

DEMO MODE (default): generates a small synthetic sample set so the whole
pipeline can be run and tested end-to-end before you've pulled real samples
from the Juliet Test Suite or OWASP Benchmark.

REAL MODE: once you've downloaded actual benchmark samples, provide a
metadata CSV (sample_id, file_path, cwe_category, ground_truth) and call
load_from_metadata_csv() — see the bottom of this file.
"""

import sqlite3
import os
import csv
from pathlib import Path

DB_PATH = "securereview.db"
DEMO_SAMPLES_DIR = "data/demo_samples"

CWE_CATEGORIES = [
    "SQL Injection (CWE-89)",
    "Command Injection (CWE-78)",
    "Path Traversal (CWE-22)",
    "Cross-Site Scripting / XSS (CWE-79)",
    "Weak Cryptography (CWE-327)",
    "Weak Hashing (CWE-328)",
    "Weak Randomness (CWE-330)",
    "Trust Boundary Violation (CWE-501)",
]

# A handful of tiny, clearly-labeled synthetic code snippets per category,
# half vulnerable / half clean, just enough to exercise the whole pipeline.
# These 8 categories match what's actually available in OWASP Benchmark --
# see prepare_owasp_samples.py for pulling real samples in these categories.
DEMO_SNIPPETS = {
    "SQL Injection (CWE-89)": [
        ('query = "SELECT * FROM users WHERE id = " + user_id\ncursor.execute(query)', "Vulnerable"),
        ('query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))', "Clean"),
    ],
    "Command Injection (CWE-78)": [
        ('os.system("ping " + user_input)', "Vulnerable"),
        ('subprocess.run(["ping", "-c", "1", user_input])', "Clean"),
    ],
    "Path Traversal (CWE-22)": [
        ('open(base_dir + user_filename)', "Vulnerable"),
        ('open(os.path.join(base_dir, os.path.basename(user_filename)))', "Clean"),
    ],
    "Cross-Site Scripting / XSS (CWE-79)": [
        ('return f"<div>{user_comment}</div>"', "Vulnerable"),
        ('return f"<div>{escape(user_comment)}</div>"', "Clean"),
    ],
    "Weak Cryptography (CWE-327)": [
        ('cipher = AES.new(key, AES.MODE_ECB)', "Vulnerable"),
        ('cipher = AES.new(key, AES.MODE_GCM)', "Clean"),
    ],
    "Weak Hashing (CWE-328)": [
        ('digest = hashlib.md5(password.encode()).hexdigest()', "Vulnerable"),
        ('digest = hashlib.sha256(password.encode()).hexdigest()', "Clean"),
    ],
    "Weak Randomness (CWE-330)": [
        ('token = random.random()', "Vulnerable"),
        ('token = secrets.token_hex(16)', "Clean"),
    ],
    "Trust Boundary Violation (CWE-501)": [
        ('session["role"] = request.args.get("role")', "Vulnerable"),
        ('session["role"] = lookup_role(current_user)', "Clean"),
    ],
}


def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS samples (
            sample_id TEXT PRIMARY KEY,
            file_path TEXT NOT NULL,
            cwe_category TEXT NOT NULL,
            ground_truth TEXT NOT NULL CHECK (ground_truth IN ('Vulnerable', 'Clean'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS results (
            sample_id TEXT NOT NULL,
            tool TEXT NOT NULL CHECK (tool IN ('ai_reviewer', 'static_baseline')),
            flagged TEXT NOT NULL CHECK (flagged IN ('Y', 'N', 'Error')),
            classification TEXT,
            raw_output TEXT,
            run_id TEXT NOT NULL,
            PRIMARY KEY (sample_id, tool, run_id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            started_at TEXT,
            ai_tool_name TEXT,
            static_tool_name TEXT,
            mode TEXT,
            sample_count INTEGER
        )
    """)
    conn.commit()
    return conn


def load_demo_samples(db_path=DB_PATH, samples_dir=DEMO_SAMPLES_DIR):
    """Generates a small synthetic sample set (16 samples, 2 per category) for testing."""
    Path(samples_dir).mkdir(parents=True, exist_ok=True)
    conn = init_db(db_path)
    conn.execute("DELETE FROM samples")

    count = 0
    for category, snippets in DEMO_SNIPPETS.items():
        for i, (code, label) in enumerate(snippets):
            safe_cat = category.split(" (")[0].replace(" ", "_").replace("/", "_")
            sample_id = f"{safe_cat}_{i:03d}"
            file_path = os.path.join(samples_dir, f"{sample_id}.py")
            with open(file_path, "w") as f:
                f.write(code)
            conn.execute(
                "INSERT INTO samples (sample_id, file_path, cwe_category, ground_truth) VALUES (?, ?, ?, ?)",
                (sample_id, file_path, category, label),
            )
            count += 1
    conn.commit()
    conn.close()
    print(f"Loaded {count} demo samples into {db_path}")
    return count


def load_from_metadata_csv(metadata_csv_path, db_path=DB_PATH):
    """
    REAL MODE: load real benchmark samples from a metadata CSV.
    Expected CSV columns: sample_id, file_path, cwe_category, ground_truth
    (ground_truth must be exactly 'Vulnerable' or 'Clean')
    """
    conn = init_db(db_path)
    conn.execute("DELETE FROM samples")
    count = 0
    skipped = []
    with open(metadata_csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            gt = row.get("ground_truth", "").strip()
            if gt not in ("Vulnerable", "Clean"):
                skipped.append(row.get("sample_id", "?"))
                continue
            if not os.path.exists(row["file_path"]):
                skipped.append(row.get("sample_id", "?"))
                continue
            conn.execute(
                "INSERT INTO samples (sample_id, file_path, cwe_category, ground_truth) VALUES (?, ?, ?, ?)",
                (row["sample_id"], row["file_path"], row["cwe_category"], gt),
            )
            count += 1
    conn.commit()
    conn.close()
    print(f"Loaded {count} real samples from {metadata_csv_path} into {db_path}")
    if skipped:
        print(f"Skipped {len(skipped)} rows (bad ground truth or missing file): {skipped[:10]}{'...' if len(skipped) > 10 else ''}")
    return count


if __name__ == "__main__":
    load_demo_samples()
