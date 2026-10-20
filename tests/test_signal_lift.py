"""Unit tests for signal lift and macro-prevalence computation."""

import pytest

from release_sentinel.signal_lift import compute_cluster_macro_prevalence, compute_lift


def test_lift_formula_exact_assertion():
    """Assert lift == (b / n_mal) / (a / n_benign) exactly."""
    b = 37
    n_mal = 179
    a = 98
    n_benign = 800

    expected = (b / n_mal) / (a / n_benign)
    actual = compute_lift(b=b, n_mal=n_mal, a=a, n_benign=n_benign)
    assert actual == pytest.approx(expected, rel=1e-9)
    assert actual == (b / n_mal) / (a / n_benign)


def test_lift_edge_cases():
    """Verify zero benign occurrences yields infinity, zero malicious yields 0."""
    assert compute_lift(b=10, n_mal=100, a=0, n_benign=800) == float("inf")
    assert compute_lift(b=0, n_mal=100, a=10, n_benign=800) == 0.0
    assert compute_lift(b=0, n_mal=100, a=0, n_benign=800) == 0.0


def test_cluster_macro_prevalence():
    """Verify cluster macro prevalence computes the unweighted mean of within-cluster fractions."""
    # Cluster 1: 2/4 pairs have signal (0.5)
    # Cluster 2: 1/1 pairs have signal (1.0)
    # Cluster 3: 0/5 pairs have signal (0.0)
    # Mean = (0.5 + 1.0 + 0.0) / 3 = 0.5
    cluster_data = [
        [True, False, True, False],
        [True],
        [False, False, False, False, False],
    ]
    macro = compute_cluster_macro_prevalence(cluster_data)
    assert macro == pytest.approx(0.5, rel=1e-9)
