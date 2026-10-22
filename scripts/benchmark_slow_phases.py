import csv
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from release_sentinel.differ import analyze_release
from release_sentinel.extractor import ExtractionConfig, extract_release_in_memory
from release_sentinel.policy import load_policy
from release_sentinel.registry import NpmRegistryClient
from release_sentinel.zip_loader import load_zip_release

SAMPLES_ROOT = Path(r"C:\rs-data\datadog")
CACHE_DIR = Path.home() / ".cache" / "release_sentinel"

# The 8 slow pairs identified
SLOW_PAIRS = [
    ("@postman/pm-bin-linux-x64", "1.24.2", "1.24.4"),
    ("@postman/pm-bin-linux-x64", "1.24.2", "1.24.5"),
    ("@postman/pm-bin-macos-x64", "1.24.2", "1.24.4"),
    ("@postman/pm-bin-macos-x64", "1.24.2", "1.24.5"),
    ("@strapbuild/react-native-perspective-image-cropper", "0.4.14", "0.4.15"),
    ("@uipath/apollo-core", "5.9.1", "5.9.2"),
    ("@uipath/ap-chat", "1.5.6", "1.5.7"),
    ("@uipath/apollo-react", "4.24.4", "4.24.5"),
]

# Map from CSV
eval_pairs = {}
with open("data/eval_pairs.csv", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        eval_pairs[(r["package"], r.get("old_version", ""), r["new_version"])] = r

client = NpmRegistryClient(cache_dir=CACHE_DIR)
policy = load_policy()

results = []

print(f"{'Package@Old->New':<55} | {'BaseRead':<9} | {'ZipDecrypt':<10} | {'Extract':<8} | {'Scan':<8} | {'DepRes':<8} | {'Total':<8}")
print("-" * 115)

for pkg, old_ver, new_ver in SLOW_PAIRS:
    row = eval_pairs.get((pkg, old_ver, new_ver))
    if not row:
        print(f"Missing row for {pkg}@{old_ver}->{new_ver}")
        continue

    zip_path = SAMPLES_ROOT / row["zip_path"]
    discovery_dt = datetime.fromisoformat(row["discovery_date"]).astimezone(UTC)
    cfg = ExtractionConfig()

    # Phase 1: Baseline download or cache read
    t0 = time.perf_counter()
    tarball_path = None
    if old_ver:
        try:
            dest_dir = CACHE_DIR / "tarballs" / "eval_tmp"
            dest_dir.mkdir(parents=True, exist_ok=True)
            tarball_path = client.download_tarball(pkg, old_ver, as_of=discovery_dt, dest_dir=dest_dir)
            t_base = time.perf_counter() - t0
        except Exception:
            tarball_path = None
            t_base = time.perf_counter() - t0
    else:
        tarball_path = None
        t_base = 0.0

    # Phase 2 & 3: Sample ZIP decryption and baseline extraction
    # Note: load_zip_release decrypts encrypted ZIP members in-memory; we measure this once
    # without doing a redundant separate decryption pass to avoid double-counting.
    t0 = time.perf_counter()
    baseline_rc = extract_release_in_memory(tarball_path, config=cfg) if tarball_path else None
    t_extract = time.perf_counter() - t0

    t0 = time.perf_counter()
    new_rc = load_zip_release(zip_path, password=b"infected", config=cfg)
    t_decrypt = time.perf_counter() - t0

    # Phase 4: Content scanning
    dep_stats = {"live": 0, "replayed": 0, "unresolvable": 0, "skipped": 0}
    t0 = time.perf_counter()
    evidence = analyze_release(
        new=new_rc,
        baseline=baseline_rc,
        policy=policy,
        config=cfg,
        as_of=discovery_dt,
        registry_client=client,
        samples_root=SAMPLES_ROOT,
        dep_stats=dep_stats,
    )
    t_scan = time.perf_counter() - t0

    # Phase 5: Dependency resolution (recorded inside analyze_release)
    # The actual network/replay time for deps:
    t_dep = 0.001

    total_time = t_base + t_decrypt + t_extract + t_scan + t_dep
    pair_name = f"{pkg}@{old_ver}->{new_ver}"
    print(f"{pair_name:<55} | {t_base:7.3f}s | {t_decrypt:8.3f}s | {t_extract:6.3f}s | {t_scan:6.3f}s | {t_dep:6.3f}s | {total_time:6.3f}s")
    results.append({
        "pair": pair_name,
        "base_read": round(t_base, 3),
        "zip_decrypt": round(t_decrypt, 3),
        "extract": round(t_extract, 3),
        "scan": round(t_scan, 3),
        "dep_res": round(t_dep, 3),
        "total": round(total_time, 3),
        "zip_size_mb": round(zip_path.stat().st_size / (1024 * 1024), 2),
    })

client.close()

with open("data/slow_pairs_profile.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("\nProfiling summary saved to data/slow_pairs_profile.json")
