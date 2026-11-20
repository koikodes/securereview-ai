"""scoring/stats.py: Wilson confidence intervals and McNemar's exact test (no SciPy needed)."""
from math import sqrt, comb

def wilson_ci(successes, n, z=1.959964):
    """95% Wilson score interval for a proportion. Returns (low, high) or (None, None) when n == 0."""
    if n == 0:
        return None, None
    p = successes / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)

def mcnemar_exact(b, c):
    """
    Exact two sided McNemar test. b = samples tool A got right and tool B got wrong,
    c = samples tool B got right and tool A got wrong. Returns the p value (1.0 if b + c == 0).
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = 2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, p)

def paired_correctness(results_a, results_b):
    """results_*: dict sample_id -> classification. Scores only samples both tools scored (TP/TN/FP/FN)."""
    b = c = 0
    for sid in set(results_a) & set(results_b):
        ca, cb = results_a[sid], results_b[sid]
        if ca not in ("TP", "TN", "FP", "FN") or cb not in ("TP", "TN", "FP", "FN"):
            continue
        a_ok, b_ok = ca in ("TP", "TN"), cb in ("TP", "TN")
        if a_ok and not b_ok: b += 1
        elif b_ok and not a_ok: c += 1
    return b, c
