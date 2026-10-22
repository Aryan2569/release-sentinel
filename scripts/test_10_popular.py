import json
from datetime import UTC, datetime
from pathlib import Path

from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, extract_release_in_memory
from release_sentinel.policy import load_policy
from release_sentinel.registry import NpmRegistryClient

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
policy = load_policy()
client = NpmRegistryClient(cache_dir=CACHE_DIR)

# The 10 packages that blocked in Stage 5h full-scan
packages_10 = [
    "query-string",
    "vite",
    "vitest",
    "@alpay_altuntas/chaperone",
    "mongodb",
    "esbuild",
    "needle",
    "@sencha/ext-modern-theme-material",
    "angular",
    "next",
]

corpus = json.load(open("data/benign_full_scan_500.json", encoding="utf-8"))
pkg_map = {p["package"]: p for p in corpus}

print("=== Comparing 10 Popular Packages ===")
for name in packages_10:
    info = pkg_map.get(name)
    if not info:
        print(f"Skipping {name}: not in corpus")
        continue

    pkg = info["package"]
    ver = info["version"]
    pub_dt = datetime.fromisoformat(info["published_at"].replace("Z", "+00:00")).astimezone(UTC)
    dest_dir = CACHE_DIR / "tarballs" / "full_scan_tmp"

    try:
        meta = client.get_metadata(pkg, as_of=pub_dt)
        time_map = meta.get("time", {})
        versions = meta.get("versions", {})

        # Find previous version
        earlier = [
            v for v in versions
            if v != ver and time_map.get(v) and time_map.get(v) < info["published_at"]
        ]
        prev_ver = max(earlier, key=lambda v: time_map.get(v, "")) if earlier else None

        tar_new = client.download_tarball(pkg, ver, as_of=pub_dt, dest_dir=dest_dir)
        cfg = ExtractionConfig()
        rc_new = extract_release_in_memory(tar_new, config=cfg)

        # 1. Tightened Full-Scan Mode
        ev_full = analyze_release(new=rc_new, baseline=None, policy=policy, config=cfg, as_of=pub_dt, registry_client=client)
        dec_full, _ = decide(ev_full, policy=policy, is_full_scan=True)

        # 2. Diff Mode against previous version
        if prev_ver:
            tar_prev = client.download_tarball(pkg, prev_ver, as_of=pub_dt, dest_dir=dest_dir)
            rc_prev = extract_release_in_memory(tar_prev, config=cfg)
            ev_diff = analyze_release(new=rc_new, baseline=rc_prev, policy=policy, config=cfg, as_of=pub_dt, registry_client=client)
            dec_diff, _ = decide(ev_diff, policy=policy, is_full_scan=False)
        else:
            dec_diff, ev_diff = dec_full, ev_full

        print(f"{pkg}@{ver} (prev: {prev_ver}):")
        print(f"  Tightened Full-Scan: {dec_full.name} -> {[e.id for e in ev_full]}")
        print(f"  New Diff Mode:      {dec_diff.name} -> {[e.id for e in ev_diff]}")
    except Exception as exc:
        print(f"{pkg}: error {exc}")

client.close()
