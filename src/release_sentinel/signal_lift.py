"""Signal Lift and Prevalence Computation (Release Sentinel Stage 5c).

Computes unit-consistent signal lift and prevalence across benign benchmarks
and malicious evaluation clusters.
"""

from __future__ import annotations

from collections.abc import Sequence


def compute_lift(
    b: int | float,
    n_mal: int | float,
    a: int | float,
    n_benign: int | float,
) -> float:
    """Compute empirical lift: (b / n_mal) / (a / n_benign).

    Parameters
    ----------
    b:
        Malicious count (e.g. number of malicious clusters containing signal,
        or macro-prevalence numerator).
    n_mal:
        Total number of malicious evaluation units (e.g. total clusters).
    a:
        Benign count (number of benign updates containing signal).
    n_benign:
        Total number of benign updates evaluated (e.g. 800).

    Returns
    -------
    float:
        Lift value. Returns float('inf') if a == 0 and b > 0.
        Returns 0.0 if b == 0.
    """
    if n_mal <= 0 or n_benign <= 0:
        raise ValueError("Sample sizes n_mal and n_benign must be positive.")

    p_mal = b / n_mal
    p_benign = a / n_benign

    if p_benign == 0.0:
        return float("inf") if p_mal > 0.0 else 0.0

    return p_mal / p_benign


def compute_cluster_macro_prevalence(
    cluster_pair_indicators: Sequence[Sequence[bool]],
) -> float:
    """Compute the cluster-macro prevalence of a signal.

    Defined as the mean over clusters of the within-cluster fraction of pairs
    containing the signal. This prevents large clusters from artificially
    inflating signal prevalence.

    Parameters
    ----------
    cluster_pair_indicators:
        A sequence where each element represents a cluster, containing a sequence
        of booleans indicating whether each pair in that cluster exhibited the signal.

    Returns
    -------
    float:
        Macro-averaged prevalence across clusters in [0.0, 1.0].
    """
    if not cluster_pair_indicators:
        return 0.0

    cluster_fractions: list[float] = []
    for pairs in cluster_pair_indicators:
        if not pairs:
            cluster_fractions.append(0.0)
        else:
            cluster_fractions.append(sum(1 for p in pairs if p) / len(pairs))

    return sum(cluster_fractions) / len(cluster_fractions)
