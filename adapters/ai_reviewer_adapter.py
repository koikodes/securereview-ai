"""
adapters/ai_reviewer_adapter.py

Adapter for the AI code review tool (example here: Snyk Code).

REAL MODE: calls the actual Snyk CLI. Requires `snyk` installed and
authenticated (`snyk auth`) on your machine. Set USE_MOCK = False once
that's done.

MOCK MODE (default, USE_MOCK = True): simulates plausible AI-tool behavior
so the rest of the pipeline can be built and tested before the real tool is
set up.

To adapt this file for a different AI tool (Copilot Code Review, CodeRabbit,
etc.), keep the same function signature — run_ai_reviewer(file_path) returns
("Y"/"N"/"Error", raw_output_string) — and change what's inside it.
"""

import subprocess
import json
import os
import shutil
import tempfile
import random

USE_MOCK = os.environ.get("SECUREREVIEW_REAL") != "1"  # set SECUREREVIEW_REAL=1 to run the real tools
def _version():
    try:
        return subprocess.run(["snyk", "--version"], capture_output=True, text=True, timeout=30).stdout.strip().splitlines()[0]
    except Exception:
        return "unknown version"


TOOL_NAME = "Snyk Code (mock)" if USE_MOCK else f"Snyk Code {_version()}"


SNYK_TIMEOUT = int(os.environ.get("SNYK_TIMEOUT", "180"))  # Snyk Code uploads and analyzes in the cloud, so 30 s is too short


def run_ai_reviewer_real(file_path):
    """
    Runs Snyk Code on one sample. Returns (flag, raw_output).

    Snyk Code scans a folder, so the sample is copied into its own temporary folder first.
    BUG-05 fix: Snyk exit codes are 0 (no issues), 1 (issues found), 2 (failure) and
    3 (no supported files). Only 0 and 1 with a well formed SARIF body are scored.
    Anything else, and any unreadable or missing file, returns "Error".
    """
    if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
        return "Error", f"Unreadable or missing file: {file_path}"
    try:
        with tempfile.TemporaryDirectory(prefix="srai_") as tmp:
            shutil.copy(file_path, os.path.join(tmp, os.path.basename(file_path)))
            result = subprocess.run(
                ["snyk", "code", "test", "--json", tmp],
                capture_output=True, text=True, timeout=SNYK_TIMEOUT,
            )
        if result.returncode not in (0, 1):
            return "Error", f"Snyk exit code {result.returncode}: {(result.stdout + result.stderr)[:300]}"
        output = json.loads(result.stdout)
        runs = output.get("runs")
        if not runs or "results" not in runs[0]:
            return "Error", "Snyk output has no runs[0].results"
        issues = runs[0]["results"]
        flag = "Y" if len(issues) > 0 else "N"
        return flag, result.stdout
    except subprocess.TimeoutExpired:
        return "Error", "Timed out"
    except (json.JSONDecodeError, IndexError, FileNotFoundError, OSError) as e:
        return "Error", f"{type(e).__name__}: {e}"


def run_ai_reviewer_mock(file_path):
    """
    Simulates an AI reviewer with realistic-ish accuracy by looking for a
    few risky-looking patterns in the sample, with some noise added so it's
    not a perfect oracle. Good enough to exercise the rest of the pipeline.
    """
    try:
        with open(file_path) as f:
            code = f.read()
    except FileNotFoundError as e:
        return "Error", str(e)

    risky_patterns = [
        "MODE_ECB", "md5(", "random.random()", "request.args.get(\"role\")",
        "os.system(", "+ user_", "pickle.loads", "hunter2", "no auth check",
        "etree.parse(user_xml_file)\n", "f\"<div>{user_comment}",
    ]
    looks_risky = any(p in code for p in risky_patterns)
    if random.random() < 0.15:  # noise, so it's not a perfect oracle
        looks_risky = not looks_risky
    flag = "Y" if looks_risky else "N"
    raw = f"[mock Snyk Code] pattern scan on {file_path}: {'issue found' if flag == 'Y' else 'no issue found'}"
    return flag, raw


def run_ai_reviewer(file_path):
    if USE_MOCK:
        return run_ai_reviewer_mock(file_path)
    return run_ai_reviewer_real(file_path)


if __name__ == "__main__":
    import sys
    test_file = sys.argv[1] if len(sys.argv) > 1 else None
    if test_file:
        print(run_ai_reviewer(test_file))
    else:
        print("Usage: python ai_reviewer_adapter.py <file_path>")
