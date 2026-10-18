"""Decision engine for Release Sentinel (Stage 2).

Thin wrapper around :mod:`policy` — delegates all logic there.
Keeps the same public signature so callers need no changes.
"""

from __future__ import annotations

from pathlib import Path

from release_sentinel.models import Decision, Evidence
from release_sentinel.policy import Policy, load_policy
from release_sentinel.policy import decide as _policy_decide


def decide(
    evidence: list[Evidence],
    policy: Policy | None = None,
    policy_path: Path | None = None,
) -> tuple[Decision, list[str]]:
    """Map *evidence* to a gate decision and a list of limitations.

    Parameters
    ----------
    evidence:
        The evidence list produced by :func:`release_sentinel.differ.compare_releases`.
    policy:
        A pre-loaded :class:`Policy` object.  Takes precedence over *policy_path*.
    policy_path:
        Path to a TOML policy file.  If both are ``None``, the bundled default is used.

    Returns
    -------
    tuple[Decision, list[str]]
        ``(decision, limitations)`` where *limitations* is a non-empty list of
        caveats that apply to this analysis regardless of the decision.
    """
    if policy is None:
        policy = load_policy(policy_path)
    return _policy_decide(evidence, policy)
