"""Regression tests for BUG-01 to BUG-05. Run: python3 -m unittest tests.test_regressions -v"""
import os, sys, sqlite3, tempfile, unittest, csv, stat, json
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data import load_dataset as L
from adapters import static_baseline_adapter as S, ai_reviewer_adapter as A


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["sample_id", "file_path", "cwe_category", "ground_truth"])
        w.writeheader(); w.writerows(rows)


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.db = os.path.join(self.d, "t.db")
        self.samples = os.path.join(self.d, "samples"); os.makedirs(self.samples)
        for n in ("a", "b"):
            open(os.path.join(self.samples, n + ".java"), "w").write("class X{}")
        self.csv = os.path.join(self.d, "m.csv")

    def row(self, sid, name, gt="Vulnerable"):
        return {"sample_id": sid, "file_path": os.path.join(self.samples, name), "cwe_category": "SQL Injection (CWE-89)", "ground_truth": gt}

    def count(self):
        c = sqlite3.connect(self.db); n = c.execute("SELECT COUNT(*) FROM samples").fetchone()[0]; c.close(); return n

    def test_bug01_outside_path_rejected(self):
        write_csv(self.csv, [self.row("ok", "a.java"), {"sample_id": "bad", "file_path": "/etc/hostname", "cwe_category": "x", "ground_truth": "Clean"}])
        self.assertEqual(L.load_from_metadata_csv(self.csv, self.db, allowed_root=self.samples), 1)

    def test_bug01_dotdot_traversal_rejected(self):
        p = os.path.join(self.samples, "..", "m.csv")
        write_csv(self.csv, [{"sample_id": "t", "file_path": p, "cwe_category": "x", "ground_truth": "Clean"}])
        self.assertEqual(L.load_from_metadata_csv(self.csv, self.db, allowed_root=self.samples), 0)

    def test_bug02_duplicate_skipped_rest_load(self):
        write_csv(self.csv, [self.row("s1", "a.java"), self.row("s1", "b.java"), self.row("s2", "b.java", "Clean")])
        self.assertEqual(L.load_from_metadata_csv(self.csv, self.db, allowed_root=self.samples), 2)

    def test_bug03_header_only_keeps_existing(self):
        write_csv(self.csv, [self.row("s1", "a.java")])
        L.load_from_metadata_csv(self.csv, self.db, allowed_root=self.samples)
        empty = os.path.join(self.d, "e.csv"); write_csv(empty, [])
        self.assertEqual(L.load_from_metadata_csv(empty, self.db, allowed_root=self.samples), 0)
        self.assertEqual(self.count(), 1)

    def test_bug03_zero_byte_csv_keeps_existing(self):
        write_csv(self.csv, [self.row("s1", "a.java")])
        L.load_from_metadata_csv(self.csv, self.db, allowed_root=self.samples)
        z = os.path.join(self.d, "z.csv"); open(z, "w").close()
        self.assertEqual(L.load_from_metadata_csv(z, self.db, allowed_root=self.samples), 0)
        self.assertEqual(self.count(), 1)

    def test_bug04_missing_csv_clear_error_no_lock(self):
        write_csv(self.csv, [self.row("s1", "a.java")])
        L.load_from_metadata_csv(self.csv, self.db, allowed_root=self.samples)
        with self.assertRaises(FileNotFoundError):
            L.load_from_metadata_csv(os.path.join(self.d, "nope.csv"), self.db)
        self.assertEqual(L.load_from_metadata_csv(self.csv, self.db, allowed_root=self.samples), 1)  # no lock
        self.assertEqual(self.count(), 1)

    def test_lowercase_label_still_rejected(self):
        write_csv(self.csv, [self.row("s1", "a.java", "vulnerable")])
        self.assertEqual(L.load_from_metadata_csv(self.csv, self.db, allowed_root=self.samples), 0)


class AdapterTests(unittest.TestCase):
    def fake(self, rc=0, out="", err=""):
        return mock.Mock(returncode=rc, stdout=out, stderr=err)

    def setUp(self):
        self.f = tempfile.NamedTemporaryFile(suffix=".java", delete=False); self.f.write(b"class X{}"); self.f.close()

    def test_missing_file_is_error(self):
        self.assertEqual(S.run_static_baseline_real("/no/such.java")[0], "Error")
        self.assertEqual(A.run_ai_reviewer_real("/no/such.java")[0], "Error")

    def test_unreadable_file_is_error(self):
        os.chmod(self.f.name, 0)
        if os.access(self.f.name, os.R_OK):
            self.skipTest("running as root, chmod 0 does not block reads")
        self.assertEqual(S.run_static_baseline_real(self.f.name)[0], "Error")

    def test_semgrep_valid_json_but_not_scanned_is_error(self):
        out = json.dumps({"results": [], "errors": [], "paths": {"scanned": [], "skipped": [{"path": self.f.name}]}})
        with mock.patch("subprocess.run", return_value=self.fake(0, out)):
            self.assertEqual(S.run_static_baseline_real(self.f.name)[0], "Error")

    def test_semgrep_fatal_error_entry_is_error(self):
        out = json.dumps({"results": [], "errors": [{"level": "error", "message": "parse"}], "paths": {"scanned": [self.f.name]}})
        with mock.patch("subprocess.run", return_value=self.fake(0, out)):
            self.assertEqual(S.run_static_baseline_real(self.f.name)[0], "Error")

    def test_semgrep_partial_parsing_warning_is_error(self):
        out = json.dumps({"results": [], "errors": [{"level": "warn", "type": ["PartialParsing", []]}], "paths": {"scanned": [self.f.name]}})
        with mock.patch("subprocess.run", return_value=self.fake(0, out)):
            self.assertEqual(S.run_static_baseline_real(self.f.name)[0], "Error")

    def test_semgrep_nonzero_exit_is_error(self):
        with mock.patch("subprocess.run", return_value=self.fake(2, "{}", "boom")):
            self.assertEqual(S.run_static_baseline_real(self.f.name)[0], "Error")

    def test_semgrep_scanned_clean_is_N_and_finding_is_Y(self):
        base = {"errors": [], "paths": {"scanned": [self.f.name]}}
        with mock.patch("subprocess.run", return_value=self.fake(0, json.dumps({**base, "results": []}))):
            self.assertEqual(S.run_static_baseline_real(self.f.name)[0], "N")
        with mock.patch("subprocess.run", return_value=self.fake(1, json.dumps({**base, "results": [{"check_id": "x"}]}))):
            self.assertEqual(S.run_static_baseline_real(self.f.name)[0], "Y")

    def test_snyk_exit_3_and_missing_runs_are_error(self):
        with mock.patch("subprocess.run", return_value=self.fake(3, "{}")):
            self.assertEqual(A.run_ai_reviewer_real(self.f.name)[0], "Error")
        with mock.patch("subprocess.run", return_value=self.fake(0, "{}")):
            self.assertEqual(A.run_ai_reviewer_real(self.f.name)[0], "Error")

    def test_snyk_clean_and_finding(self):
        with mock.patch("subprocess.run", return_value=self.fake(0, json.dumps({"runs": [{"results": []}]}))):
            self.assertEqual(A.run_ai_reviewer_real(self.f.name)[0], "N")
        with mock.patch("subprocess.run", return_value=self.fake(1, json.dumps({"runs": [{"results": [{}]}]}))):
            self.assertEqual(A.run_ai_reviewer_real(self.f.name)[0], "Y")


if __name__ == "__main__":
    unittest.main()
