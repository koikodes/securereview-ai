"""
data/prepare_owasp_samples.py

Pulls a stratified sample from a downloaded OWASP Benchmark checkout, copies
the needed .java files into this project, and builds the metadata CSV that
load_from_metadata_csv() expects.

This project uses 8 CWE categories that OWASP Benchmark has real test cases
for: Path Traversal, Command Injection, SQL Injection, XSS, Weak Cryptography,
Weak Hashing, Weak Randomness, and Trust Boundary Violation.

Usage:
    1. Download OWASP Benchmark:
       https://github.com/OWASP-Benchmark/BenchmarkJava -> Code -> Download ZIP
       Unzip it somewhere (e.g. your Downloads folder).

    2. Run this script, pointing it at the unzipped folder:
       python3 data/prepare_owasp_samples.py /path/to/BenchmarkJava-master --per-category 40

This copies the selected .java files into data/owasp_samples/ and writes
data/owasp_metadata.csv, ready to load with:
    python3 -c "from data.load_dataset import load_from_metadata_csv; load_from_metadata_csv('data/owasp_metadata.csv')"
"""

import argparse
import csv
import os
import random
import shutil

# Maps OWASP Benchmark's internal category codes to this project's CWE categories.
# Only categories in this project's scope are included; the three small ones in
# OWASP Benchmark (ldapi, securecookie, xpathi) are skipped because they have
# too few samples (under 40 total each) for a balanced sample.
CATEGORY_MAP = {
    "pathtraver": "Path Traversal (CWE-22)",
    "cmdi": "Command Injection (CWE-78)",
    "sqli": "SQL Injection (CWE-89)",
    "xss": "Cross-Site Scripting / XSS (CWE-79)",
    "crypto": "Weak Cryptography (CWE-327)",
    "hash": "Weak Hashing (CWE-328)",
    "weakrand": "Weak Randomness (CWE-330)",
    "trustbound": "Trust Boundary Violation (CWE-501)",
}


def prepare_samples(benchmark_dir, per_category=40, seed=42, out_dir="data/owasp_samples", out_csv="data/owasp_metadata.csv"):
    expected_csv = os.path.join(benchmark_dir, "expectedresults-1.2.csv")
    testcode_dir = os.path.join(benchmark_dir, "src", "main", "java", "org", "owasp", "benchmark", "testcode")

    if not os.path.exists(expected_csv):
        raise FileNotFoundError(f"Could not find expectedresults-1.2.csv in {benchmark_dir}. Check the path you gave points at the unzipped BenchmarkJava folder.")
    if not os.path.isdir(testcode_dir):
        raise FileNotFoundError(f"Could not find the testcode source folder under {benchmark_dir}. Check the download wasn't partial.")

    # Read every row, grouped by our target category
    rows_by_category = {cat: [] for cat in CATEGORY_MAP.values()}
    with open(expected_csv, newline="") as f:
        reader = csv.reader(f)
        next(reader)  # skip header/comment line
        for row in reader:
            if len(row) < 4:
                continue
            test_name, owasp_category, real_vuln, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            if owasp_category not in CATEGORY_MAP:
                continue
            ground_truth = "Vulnerable" if real_vuln.lower() == "true" else "Clean"
            rows_by_category[CATEGORY_MAP[owasp_category]].append((test_name, ground_truth))

    random.seed(seed)
    os.makedirs(out_dir, exist_ok=True)
    metadata_rows = []
    summary = {}

    for category, entries in rows_by_category.items():
        vulnerable = [e for e in entries if e[1] == "Vulnerable"]
        clean = [e for e in entries if e[1] == "Clean"]
        random.shuffle(vulnerable)
        random.shuffle(clean)

        half = per_category // 2
        selected = vulnerable[:half] + clean[:half]
        random.shuffle(selected)

        copied = 0
        for test_name, ground_truth in selected:
            src_file = os.path.join(testcode_dir, f"{test_name}.java")
            if not os.path.exists(src_file):
                continue
            dst_file = os.path.join(out_dir, f"{test_name}.java")
            shutil.copy(src_file, dst_file)
            metadata_rows.append({
                "sample_id": test_name,
                "file_path": dst_file,
                "cwe_category": category,
                "ground_truth": ground_truth,
            })
            copied += 1

        summary[category] = {
            "available_vulnerable": len(vulnerable),
            "available_clean": len(clean),
            "copied": copied,
        }

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "file_path", "cwe_category", "ground_truth"])
        writer.writeheader()
        writer.writerows(metadata_rows)

    print(f"Wrote {len(metadata_rows)} samples to {out_csv}, files copied to {out_dir}/\n")
    print("Per-category breakdown:")
    for category, s in summary.items():
        print(f"  {category}: {s['copied']} copied (had {s['available_vulnerable']} vulnerable, {s['available_clean']} clean available)")

    return out_csv


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("benchmark_dir", help="Path to the unzipped OWASP BenchmarkJava folder")
    parser.add_argument("--per-category", type=int, default=40, help="How many samples to take per CWE category (split evenly between vulnerable/clean). Default 40.")
    parser.add_argument("--out-dir", default="data/owasp_samples")
    parser.add_argument("--out-csv", default="data/owasp_metadata.csv")
    args = parser.parse_args()
    prepare_samples(args.benchmark_dir, per_category=args.per_category, out_dir=args.out_dir, out_csv=args.out_csv)
