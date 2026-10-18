"""Policy engine for Release Sentinel.

Loads a TOML policy file and uses corroboration rules to make the
final ALLOW / WARN / BLOCK decision.

Design (replacing the naïve max-severity rule)
----------------------------------------------
* A single signal — no matter how severe — caps at ``single_signal_cap`` (default WARN).
* BLOCK is issued only when a corroboration pair is satisfied AND the corroborated
  signals include at least one HIGH or CRITICAL item.
* Per-evidence severity overrides in the TOML are applied before the decision rules.

Rule 4 (Evidence, not verdicts): limitations are always non-empty.
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from release_sentinel.models import Decision, Evidence, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class BlockRequires:
    """A pair of evidence IDs that, when both present, allow a BLOCK decision."""

    signals: list[str]
    description: str = ""


@dataclass
class Policy:
    """Parsed policy configuration."""

    single_signal_cap: Decision = Decision.WARN
    block_requires: list[BlockRequires] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)


# Limitations that are always true regardless of policy
_STATIC_LIMITATIONS: list[str] = [
    "JavaScript/TypeScript source is scanned with regex heuristics, not fully parsed — "
    "obfuscated code may evade detection.",
    "Transitive (indirect) dependencies are not analysed.",
    "Known vulnerability databases (OSV, NVD, npm advisory) are not consulted.",
    "Binary files (.node, .wasm, compiled extensions) cannot be inspected for malicious content.",
    "'No evidence found' does not mean 'safe' — it means nothing suspicious was detected "
    "by these specific checks at this point in time.",
]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_policy(policy_path: Path | None = None) -> Policy:
    """Load and return a :class:`Policy`.

    Starts from the bundled default, then overlays the user-supplied file.

    Parameters
    ----------
    policy_path:
        Path to a user TOML policy file.  If ``None``, only the default is used.
    """
    # Load the bundled default
    default_path = _default_policy_path()
    raw = _load_toml(default_path)

    # Overlay user file
    if policy_path is not None:
        user_raw = _load_toml(policy_path)
        raw = _deep_merge(raw, user_raw)

    return _parse_policy(raw)


def _default_policy_path() -> Path:
    """Return the path to the bundled default policy TOML."""
    # Try the data/ directory relative to the package root first
    candidate = Path(__file__).parent.parent.parent / "data" / "policy_default.toml"
    if candidate.exists():
        return candidate
    # Fallback: try importlib.resources (for installed distributions)
    try:
        ref = resources.files("release_sentinel").joinpath("../../data/policy_default.toml")
        return Path(str(ref))
    except Exception:  # noqa: BLE001
        raise FileNotFoundError(
            "Cannot locate data/policy_default.toml. "
            "Make sure the package is installed correctly."
        ) from None


def _load_toml(path: Path) -> dict:
    """Load a TOML file and return the raw dict."""
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"Cannot load policy from {path}: {exc}") from exc


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge *overlay* into *base*."""
    result = dict(base)
    for key, val in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _parse_policy(raw: dict) -> Policy:
    """Parse a raw TOML dict into a :class:`Policy`."""
    decision_raw = raw.get("decision", {})
    cap_str = decision_raw.get("single_signal_cap", "WARN").upper()
    try:
        cap = Decision(cap_str)
    except ValueError:
        cap = Decision.WARN
        logger.warning("Unknown single_signal_cap %r; defaulting to WARN", cap_str)

    block_requires: list[BlockRequires] = []
    for entry in decision_raw.get("block_requires", []):
        signals = entry.get("signals", [])
        if len(signals) >= 2:
            block_requires.append(
                BlockRequires(signals=signals, description=entry.get("description", ""))
            )

    sev_overrides: dict[str, Severity] = {}
    for ev_id, sev_str in raw.get("severity_overrides", {}).items():
        try:
            sev_overrides[ev_id] = Severity(sev_str.upper())
        except ValueError:
            logger.warning("Unknown severity %r for %r in policy; ignoring", sev_str, ev_id)

    return Policy(
        single_signal_cap=cap,
        block_requires=block_requires,
        severity_overrides=sev_overrides,
    )


# ---------------------------------------------------------------------------
# Decision engine
# ---------------------------------------------------------------------------


def decide(
    evidence: list[Evidence],
    policy: Policy | None = None,
) -> tuple[Decision, list[str]]:
    """Apply *policy* to *evidence* and return ``(decision, limitations)``.

    Parameters
    ----------
    evidence:
        Evidence list from the differ + content scanner.
    policy:
        Policy to use.  Loads the default policy if ``None``.

    Returns
    -------
    tuple[Decision, list[str]]
        The gate decision and a non-empty list of limitations.
    """
    if policy is None:
        policy = load_policy()

    limitations = list(_STATIC_LIMITATIONS)

    if not evidence:
        return Decision.ALLOW, limitations

    # Apply severity overrides
    effective = _apply_overrides(evidence, policy.severity_overrides)

    # INFO-level evidence never alerts
    alerting = [ev for ev in effective if ev.severity != Severity.INFO]

    if not alerting:
        return Decision.ALLOW, limitations

    # Collect distinct signal IDs present in alerting evidence
    signal_ids = {ev.id for ev in alerting}

    # Single-signal rule: only one distinct alerting signal type
    if len(signal_ids) == 1:
        max_sev = _max_severity(alerting)
        if max_sev == Severity.LOW:
            # A single LOW signal -> ALLOW (evidence still listed in the report)
            return Decision.ALLOW, limitations
        if max_sev == Severity.MEDIUM:
            # A single MEDIUM -> WARN
            return Decision.WARN, limitations
        # Single HIGH or CRITICAL signal -> capped at single_signal_cap (default WARN)
        final = max(policy.single_signal_cap, Decision.WARN, key=_decision_order)
        return final, limitations

    # Multi-signal: check corroboration pairs for BLOCK
    # BLOCK still requires corroboration of at least two distinct signals
    for pair in policy.block_requires:
        if all(sig in signal_ids for sig in pair.signals):
            # Corroboration satisfied — check that at least one HIGH/CRITICAL present
            matching_ev = [ev for ev in alerting if ev.id in pair.signals]
            if any(ev.severity in (Severity.HIGH, Severity.CRITICAL) for ev in matching_ev):
                return Decision.BLOCK, limitations

    # Multi-signal but no corroboration pair matches
    max_sev = _max_severity(alerting)
    if max_sev == Severity.LOW:
        # Check if any corroboration pair was matched (all-low pair falls back to WARN)
        any_pair_matched = any(
            all(sig in signal_ids for sig in pair.signals)
            for pair in policy.block_requires
        )
        if any_pair_matched:
            return Decision.WARN, limitations
        return Decision.ALLOW, limitations

    return Decision.WARN, limitations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _apply_overrides(
    evidence: list[Evidence], overrides: dict[str, Severity]
) -> list[Evidence]:
    """Return a new list with per-evidence severity overrides applied."""
    result: list[Evidence] = []
    for ev in evidence:
        if ev.id in overrides:
            result.append(ev.model_copy(update={"severity": overrides[ev.id]}))
        else:
            result.append(ev)
    return result


def _max_severity(evidence: list[Evidence]) -> Severity:
    _order = {
        Severity.INFO: -1,
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }
    return max(evidence, key=lambda e: _order[e.severity]).severity


def _decision_order(d: Decision) -> int:
    return {Decision.ALLOW: 0, Decision.WARN: 1, Decision.BLOCK: 2}[d]
