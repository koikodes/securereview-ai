import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scoring.stats import wilson_ci, mcnemar_exact, paired_correctness

class StatsTests(unittest.TestCase):
    def test_wilson_known_value(self):
        lo, hi = wilson_ci(8, 10)          # textbook example: 0.490 to 0.943
        self.assertAlmostEqual(lo, 0.4902, places=3); self.assertAlmostEqual(hi, 0.9433, places=3)
    def test_wilson_edges(self):
        self.assertEqual(wilson_ci(0, 0), (None, None))
        lo, hi = wilson_ci(10, 10); self.assertAlmostEqual(hi, 1.0, places=9); self.assertLess(lo, 1.0)
    def test_mcnemar_known_values(self):
        self.assertAlmostEqual(mcnemar_exact(0, 10), 2 / 1024, places=9)   # 0.001953
        self.assertEqual(mcnemar_exact(5, 5), 1.0)
        self.assertEqual(mcnemar_exact(0, 0), 1.0)
        self.assertAlmostEqual(mcnemar_exact(2, 9), 134 / 2048, places=9)    # 2*(1+11+55)/2^11
    def test_pairing_ignores_errors(self):
        a = {"1": "TP", "2": "FN", "3": "Error", "4": "TN"}
        b = {"1": "FN", "2": "TP", "3": "TP", "4": "TN"}
        self.assertEqual(paired_correctness(a, b), (1, 1))
if __name__ == "__main__":
    unittest.main()
