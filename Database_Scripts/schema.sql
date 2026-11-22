-- SecureReview AI database schema (SQLite). The application creates this automatically
-- on first run (data/load_dataset.py, init_db). This copy is for reference and for
-- building the database by hand:  sqlite3 securereview.db < schema.sql

CREATE TABLE IF NOT EXISTS samples (
    sample_id    TEXT PRIMARY KEY,
    file_path    TEXT NOT NULL,
    cwe_category TEXT NOT NULL,
    ground_truth TEXT NOT NULL CHECK (ground_truth IN ('Vulnerable', 'Clean'))
);

CREATE TABLE IF NOT EXISTS results (
    sample_id      TEXT NOT NULL,
    tool           TEXT NOT NULL CHECK (tool IN ('ai_reviewer', 'static_baseline')),
    flagged        TEXT NOT NULL CHECK (flagged IN ('Y', 'N', 'Error')),
    classification TEXT,            -- TP, FP, FN, TN, Error
    raw_output     TEXT,            -- raw tool output kept for audit
    run_id         TEXT NOT NULL,
    PRIMARY KEY (sample_id, tool, run_id)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id           TEXT PRIMARY KEY,
    started_at       TEXT,          -- UTC, ISO 8601
    ai_tool_name     TEXT,
    static_tool_name TEXT,
    mode             TEXT,          -- pilot or full
    sample_count     INTEGER
);
