"""End-to-end evaluation pair analysis for Release Sentinel (Stage 3a).

Rule 7 compliance:
- Malicious samples stay in their encrypted ZIPs at rest.
- New release is loaded directly into memory via zip_loader without writing to disk.
- Old benign release is fetched from registry and loaded in memory via extract_release_in_memory.
- Time cut-off (as_of) is set to the discovery date as an upper bound (publish date unknown).
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from release_sentinel.differ import compare_releases
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, ReleaseContents, extract_release_in_memory
from release_sentinel.models import Decision, Evidence
from release_sentinel.policy import Policy
from release_sentinel.registry import NpmRegistryClient
from release_sentinel.zip_loader import load_zip_release

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "release_sentinel"


@dataclass
class EvalPairResult:
    """Outcome of analyzing a single compromised evaluation pair."""

    package: str
    old_version: str
    new_version: str
    discovery_date: str
    decision: Decision
    evidence: list[Evidence]
    limitations: list[str]
    payload_hashes: list[str] = field(default_factory=list)


def parse_discovery_date_as_of(discovery_date: str | datetime) -> datetime:
    """Convert discovery date into a UTC datetime for the as_of cut-off.

    Note on as_of:
    In the DataDog dataset, the date in each file name is the DISCOVERY date,
    not the package publication date. We treat the end of the discovery date
    (23:59:59 UTC) as a strict upper bound because the exact publish timestamp
    is unknown.
    """
    if isinstance(discovery_date, datetime):
        if discovery_date.tzinfo:
            return discovery_date.astimezone(UTC)
        return discovery_date.replace(tzinfo=UTC)

    # Expected format: YYYY-MM-DD
    dt_str = discovery_date.strip()
    if len(dt_str) == 10 and dt_str.count("-") == 2:
        return datetime.fromisoformat(f"{dt_str}T23:59:59+00:00").astimezone(UTC)

    # General ISO format fallback
    parsed = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def analyze_eval_pair(
    package: str,
    old_version: str,
    zip_path: Path | str,
    discovery_date: str | datetime,
    new_version: str | None = None,
    registry_client: NpmRegistryClient | None = None,
    policy: Policy | None = None,
    config: ExtractionConfig | None = None,
) -> EvalPairResult:
    """Analyze one eval pair end-to-end completely in memory.

    Parameters
    ----------
    package:
        npm package name (e.g. "02-echo" or "@accordproject/concerto-metamodel").
    old_version:
        Known benign baseline version to fetch from npm registry.
    zip_path:
        Path to the encrypted sample ZIP file on disk.
    discovery_date:
        Discovery date string (YYYY-MM-DD) or datetime; used as as_of upper bound.
    new_version:
        Optional new malicious version string; inferred if not provided.
    registry_client:
        Optional NpmRegistryClient. If None, a client with the default cache dir is used.
    policy:
        Optional detection policy. If None, bundled default policy is used.
    config:
        Optional extraction caps and limits.

    Returns
    -------
    EvalPairResult
        Gate decision (ALLOW / WARN / BLOCK), evidence list, and limitations.
    """
    as_of = parse_discovery_date_as_of(discovery_date)
    zip_path = Path(zip_path)

    # 1. Load new compromised release from encrypted ZIP in memory
    logger.debug("Loading compromised release from %s into memory...", zip_path)
    new_release = load_zip_release(zip_path, password=b"infected", config=config)

    inferred_new_ver = new_version
    if not inferred_new_ver:
        pj = new_release.package_json()
        if pj and isinstance(pj.get("version"), str):
            inferred_new_ver = pj["version"]
        else:
            # Fallback to parsing filename, e.g. YYYY-MM-DD-pkg-vX.Y.Z.zip
            m = re.search(r"-v([0-9a-zA-Z._-]+)\.zip$", zip_path.name)
            inferred_new_ver = m.group(1) if m else "unknown"

    # 2. Fetch and load old benign release from registry in memory
    owned_client = False
    if registry_client is None:
        registry_client = NpmRegistryClient(cache_dir=_DEFAULT_CACHE_DIR)
        owned_client = True

    try:
        dest_temp = _DEFAULT_CACHE_DIR / "tarballs" / "eval_tmp"
        tarball_path = registry_client.download_tarball(
            name=package,
            version=old_version,
            as_of=as_of,
            dest_dir=dest_temp,
        )
        logger.debug("Loading baseline release %s@%s into memory...", package, old_version)
        old_release = extract_release_in_memory(tarball_path, config=config)
    finally:
        if owned_client:
            registry_client.close()

    # 3. Static diff in memory
    evidence = compare_releases(old_release, new_release)

    # 4. Policy decision
    decision, limitations = decide(evidence, policy=policy)

    # 5. Payload hashes for campaign clustering
    payload_hashes = compute_payload_hashes(old_release, new_release)

    return EvalPairResult(
        package=package,
        old_version=old_version,
        new_version=inferred_new_ver,
        discovery_date=(
            discovery_date
            if isinstance(discovery_date, str)
            else discovery_date.strftime("%Y-%m-%d")
        ),
        decision=decision,
        evidence=evidence,
        limitations=limitations,
        payload_hashes=payload_hashes,
    )


def compute_payload_hashes(
    old_release: ReleaseContents,
    new_release: ReleaseContents,
) -> list[str]:
    """Compute SHA-256 hashes of new or changed files for campaign clustering.

    Ignores:
    - package.json
    - README*
    - LICENSE* / LICENCE*
    - *.map (source maps)
    - files under 200 bytes
    """
    hashes: set[str] = set()
    old_files = old_release.files
    for rel_path, new_bytes in new_release.files.items():
        filename = Path(rel_path).name.lower()
        if filename == "package.json":
            continue
        if filename.startswith("readme"):
            continue
        if filename.startswith("license") or filename.startswith("licence"):
            continue
        if filename.endswith(".map"):
            continue
        if len(new_bytes) < 200:
            continue

        if rel_path not in old_files or old_files[rel_path] != new_bytes:
            hashes.add(hashlib.sha256(new_bytes).hexdigest())

    return sorted(hashes)

