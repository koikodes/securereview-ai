"""
adapters/static_baseline_adapter.py

Adapter for the static analysis baseline tool (example here: Semgrep).

REAL MODE: calls the actual Semgrep CLI (`pip install semgrep`). Set
USE_MOCK = False once it's installed.

MOCK MODE (default, USE_MOCK = True): simulates plausible static-analysis
behavior (pattern matching, no noise, since static tools are deterministic)
so the rest of the pipeline can be built and tested first.

Same function shape as the AI reviewer adapter on purpose: run_static_baseline
(file_path) returns ("Y"/"N"/"Error", raw_output_string). That's what lets
the orchestrator call either adapter the same way.
"""

import subprocess
import json
import os

USE_MOCK = os.environ.get("SECUREREVIEW_REAL") != "1"  # set SECUREREVIEW_REAL=1 to run the real tools
def _version():
    try:  # instant and needs no network, works when semgrep is installed in this environment
        from importlib.metadata import version
        return version("semgrep")
    except Exception:
        pass
    try:
        return subprocess.run(["semgrep", "--version", "--disable-version-check"], capture_output=True, text=True, timeout=60).stdout.strip().splitlines()[-1]
    except Exception:
        return "unknown version"


TOOL_NAME = "Semgrep (mock)" if USE_MOCK else f"Semgrep {_version()}"


SEMGREP_TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT", "120"))  # seconds per file, 30 was too short on a busy laptop
SEMGREP_CONFIG = os.environ.get("SEMGREP_CONFIG", "auto")  # e.g. a local rules folder when offline


def run_static_baseline_real(file_path):
    """
    Runs Semgrep on one sample. Returns (flag, raw_output).

    BUG-05 fix: a result is only "N" when Semgrep confirms it scanned the file with no
    fatal errors. A missing or unreadable file, a nonzero exit code other than 0 or 1,
    a fatal error entry, or a file that was skipped or never scanned all return "Error"
    so the sample is excluded from scoring instead of counted as a false negative.
    """
    if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
        return "Error", f"Unreadable or missing file: {file_path}"
    try:
        result = subprocess.run(
            ["semgrep", f"--config={SEMGREP_CONFIG}", "--json", "--metrics=off",
             "--disable-version-check", file_path],
            capture_output=True, text=True, timeout=SEMGREP_TIMEOUT,
        )
        if result.returncode not in (0, 1):
            return "Error", f"Semgrep exit code {result.returncode}: {result.stderr[:300]}"
        output = json.loads(result.stdout)
        # Any entry in "errors" means the analysis may be incomplete. Semgrep reports an
        # unparseable file as a level "warn" PartialParsing entry with exit code 0 and zero
        # results, which the first version of this fix still scored as N (found by running
        # the real tool on a garbage .java file).
        errs = output.get("errors", [])
        if errs:
            return "Error", f"Semgrep reported errors: {json.dumps(errs)[:300]}"
        paths = output.get("paths", {})
        scanned = [os.path.normpath(x) for x in paths.get("scanned", [])]
        if os.path.normpath(file_path) not in scanned:
            return "Error", "Semgrep did not scan the file (skipped or unsupported)"
        findings = output.get("results", [])
        flag = "Y" if len(findings) > 0 else "N"
        return flag, result.stdout
    except subprocess.TimeoutExpired:
        return "Error", "Timed out"
    except (json.JSONDecodeError, FileNotFoundError) as e:
        return "Error", f"{type(e).__name__}: {e}"


def run_static_baseline_mock(file_path):
    """
    Simulates a static analyzer: deterministic pattern matching, no noise,
    since real static tools are consistent (same input -> same output).
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
        "+ user_id", "+ user_input", "+ user_filename",
    ]
    looks_risky = any(p in code for p in risky_patterns)
    flag = "Y" if looks_risky else "N"
    raw = f"[mock Semgrep] rule scan on {file_path}: {'finding' if flag == 'Y' else 'no finding'}"
    return flag, raw


def run_static_baseline(file_path):
    if USE_MOCK:
        return run_static_baseline_mock(file_path)
    return run_static_baseline_real(file_path)


if __name__ == "__main__":
    import sys
    test_file = sys.argv[1] if len(sys.argv) > 1 else None
    if test_file:
        print(run_static_baseline(test_file))
    else:
        print("Usage: python static_baseline_adapter.py <file_path>")
