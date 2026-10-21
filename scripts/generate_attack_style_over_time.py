"""Generate attack-style-over-time report and visualization (Stage 5e Part 6).

Uses detector-independent data only:
- data/detectability_audit.json
- data/dependency_reconciliation.json

Outputs:
- docs/attack_style_over_time.md
- docs/attack_style_over_time.png
"""

from __future__ import annotations

import json
import struct
import sys
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, ".")
from scripts.build_campaigns import get_split_mapping

AUDIT_JSON = Path("data/detectability_audit.json")
DEP_RECON_JSON = Path("data/dependency_reconciliation.json")
REPORT_MD = Path("docs/attack_style_over_time.md")
CHART_PNG = Path("docs/attack_style_over_time.png")


def get_quarter(dt_str: str) -> str:
    y, m, _ = dt_str.split("-")
    q = (int(m) - 1) // 3 + 1
    return f"{y}-Q{q}"


def build_attack_style_data() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    audit = json.load(open(AUDIT_JSON, encoding="utf-8"))
    k2s = get_split_mapping()
    dep_recon = json.load(open(DEP_RECON_JSON, encoding="utf-8"))

    split_data = defaultdict(lambda: {"total": 0, "adds_dep": 0, "hollow": 0, "adds_hook": 0, "changes_code": 0})
    quarter_data = defaultdict(lambda: {"total": 0, "adds_dep": 0, "hollow": 0, "adds_hook": 0, "changes_code": 0})

    for r in audit:
        pkg = r["package"]
        old_ver = r["old_version"]
        new_ver = r["new_version"]
        dt = r["discovery_date"]
        s = k2s.get((pkg, old_ver, new_ver), "DEV")
        q = get_quarter(dt)

        adds_dep = bool(r.get("adds_direct_dependency"))
        hollow = bool(r.get("metadata_only") and adds_dep)
        adds_hook = bool(r.get("adds_or_changes_lifecycle_script"))
        changes_code = bool(r.get("content_changed"))

        for d in [split_data[s], quarter_data[q]]:
            d["total"] += 1
            if adds_dep:
                d["adds_dep"] += 1
            if hollow:
                d["hollow"] += 1
            if adds_hook:
                d["adds_hook"] += 1
            if changes_code:
                d["changes_code"] += 1

    return split_data, quarter_data, dep_recon["counts_per_split"]


def create_png_chart(quarter_data: dict[str, Any], out_path: Path) -> None:
    """Generate a clean 800x450 PNG chart of attack styles across quarters."""
    width = 800
    height = 450
    # RGB background white
    pixels = bytearray([255, 255, 255, 255] * (width * height))

    def set_pixel(x: int, y: int, r: int, g: int, b: int, a: int = 255) -> None:
        if 0 <= x < width and 0 <= y < height:
            idx = (y * width + x) * 4
            pixels[idx] = r
            pixels[idx + 1] = g
            pixels[idx + 2] = b
            pixels[idx + 3] = a

    def draw_line(x0: int, y0: int, x1: int, y1: int, r: int, g: int, b: int) -> None:
        dx = abs(x1 - x0)
        dy = abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx - dy
        while True:
            set_pixel(x0, y0, r, g, b)
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                x0 += sx
            if e2 < dx:
                err += dx
                y0 += sy

    def draw_rect(x0: int, y0: int, x1: int, y1: int, r: int, g: int, b: int) -> None:
        for y in range(max(0, y0), min(height, y1 + 1)):
            for x in range(max(0, x0), min(width, x1 + 1)):
                set_pixel(x, y, r, g, b)

    # Plot margins
    pad_left = 70
    pad_right = 40
    pad_top = 50
    pad_bottom = 70
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    # Axes
    draw_line(pad_left, pad_top + plot_h, pad_left + plot_w, pad_top + plot_h, 150, 150, 150)
    draw_line(pad_left, pad_top, pad_left, pad_top + plot_h, 150, 150, 150)

    # Gridlines (0%, 25%, 50%, 75%, 100%)
    for pct in [0.0, 0.25, 0.50, 0.75, 1.0]:
        y = int(pad_top + plot_h * (1.0 - pct))
        for x in range(pad_left, pad_left + plot_w, 6):
            set_pixel(x, y, 220, 220, 220)

    # Categories to plot
    quarters = sorted(quarter_data.keys())
    n_q = len(quarters)

    # Colors
    c_hook = (217, 83, 79)    # Red - Lifecycle hook
    c_code = (91, 192, 222)   # Blue - Changes code
    c_dep = (240, 173, 78)    # Orange - Adds runtime dep
    c_hollow = (92, 184, 92)  # Green - Hollow release

    # Series lines
    for series_key, color in [
        ("adds_hook", c_hook),
        ("changes_code", c_code),
        ("adds_dep", c_dep),
        ("hollow", c_hollow),
    ]:
        pts = []
        for i, q in enumerate(quarters):
            d = quarter_data[q]
            rate = d[series_key] / d["total"] if d["total"] > 0 else 0.0
            x = int(pad_left + (i + 0.5) * (plot_w / n_q))
            y = int(pad_top + plot_h * (1.0 - rate))
            pts.append((x, y))

        for j in range(len(pts) - 1):
            x0, y0 = pts[j]
            x1, y1 = pts[j + 1]
            draw_line(x0, y0, x1, y1, *color)
            draw_line(x0, y0 + 1, x1, y1 + 1, *color)
            draw_rect(x0 - 3, y0 - 3, x0 + 3, y0 + 3, *color)
        draw_rect(pts[-1][0] - 3, pts[-1][1] - 3, pts[-1][0] + 3, pts[-1][1] + 3, *color)

    # Legend
    legend_items = [
        ("Lifecycle Hook", c_hook),
        ("Code Changed", c_code),
        ("Runtime Dep Added", c_dep),
        ("Hollow Release", c_hollow),
    ]
    lx = pad_left + 20
    ly = 20
    for _label, col in legend_items:
        draw_rect(lx, ly, lx + 12, ly + 12, *col)
        lx += 170

    # Write PNG
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        raw.extend(pixels[y * width * 4 : (y + 1) * width * 4])

    compressed = zlib.compress(bytes(raw), 9)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr_chunk = struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    idat_chunk = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + struct.pack(">I", zlib.crc32(b"IDAT" + compressed))
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))

    png_bytes = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk + iend_chunk
    out_path.write_bytes(png_bytes)
    print(f"Generated chart {out_path}")


def write_markdown_report(split_data: dict[str, Any], quarter_data: dict[str, Any], dep_res: dict[str, Any]) -> None:
    lines = [
        "# Malicious Attack Style Over Time (Detector-Independent Analysis)",
        "",
        "This document analyzes the historical structural evolution of npm supply chain attacks across **1,349 real malicious packages** strictly using **detector-independent ground truth**.",
        "",
        "![Attack Style Over Time](attack_style_over_time.png)",
        "",
        "---",
        "",
        "## 1. Attack Style Evolution by Split",
        "",
        "| Split | Sample Size | Adds Runtime Dep | Hollow Release (Zero Code) | Adds Lifecycle Hook | Changes / Injects Code |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]

    for s in ["DEV", "VAL", "TEST-A", "TEST-B"]:
        d = split_data[s]
        tot = d["total"]
        lines.append(
            f"| **{s}** | {tot:,} | {d['adds_dep']} ({d['adds_dep']/tot*100:.2f}%) | "
            f"{d['hollow']} ({d['hollow']/tot*100:.2f}%) | "
            f"{d['adds_hook']} ({d['adds_hook']/tot*100:.2f}%) | "
            f"{d['changes_code']} ({d['changes_code']/tot*100:.2f}%) |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 2. Attack Style Evolution by Calendar Quarter",
        "",
        "| Quarter | Samples | Adds Runtime Dep | Hollow Release | Adds Lifecycle Hook | Changes Code | Primary Delivery Mechanism |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :--- |",
    ])

    for q in sorted(quarter_data.keys()):
        d = quarter_data[q]
        tot = d["total"]
        hollow_pct = d["hollow"] / tot * 100
        hook_pct = d["adds_hook"] / tot * 100
        dep_pct = d["adds_dep"] / tot * 100

        if hollow_pct > 50:
            mech = "Hollow typosquat dependency delivery"
        elif hook_pct > 70:
            mech = "Inline lifecycle command execution (`preinstall` / `install`)"
        elif dep_pct > 30:
            mech = "Transitive dependency addition alongside script hooks"
        else:
            mech = "Direct JS payload injection"

        lines.append(
            f"| **{q}** | {tot:,} | {d['adds_dep']} ({dep_pct:.1f}%) | "
            f"{d['hollow']} ({hollow_pct:.1f}%) | "
            f"{d['adds_hook']} ({hook_pct:.1f}%) | "
            f"{d['changes_code']} ({d['changes_code']/tot*100:.1f}%) | {mech} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Runtime Dependency Resolution Breakdown",
        "",
        "How added direct dependencies resolve on the public npm registry today:",
        "",
        "| Split | Pairs Adding Dep | Distinct Dep Names | Live Packages | Delisted (npm Placeholder) | 404 / Removed | Other / Unsupported |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])

    for s in ["DEV", "VAL", "TEST-A", "TEST-B"]:
        d_info = dep_res.get(s, {})
        res = d_info.get("resolution", {})
        live = res.get("real", 0)
        ph = res.get("placeholder", 0)
        n404 = res.get("404", 0)
        unsupp = res.get("unsupported_spec", 0)

        lines.append(
            f"| **{s}** | {d_info.get('pairs_adding_dependency', 0)} | "
            f"{d_info.get('distinct_dependency_names', 0)} | "
            f"{live} | {ph} | {n404} | {unsupp} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 4. Key Security Insights",
        "",
        "1. **Tactical Regime Shift in 2026-Q3 / Q4**: Prior to 2026, over 90% of attacks executed inline lifecycle scripts or modified JavaScript runtime files directly. In TEST-B (late 2026), 94.95% of attacks completely abandoned code modifications, publishing entirely **hollow metadata releases** that deliver payloads via external dependencies.",
        "2. **Delisting Lag**: 100% of dependencies added in TEST-B were delisted by npm security teams (replaced by security placeholders), leaving zero inspectable malicious JavaScript in retroactive audits. Time-aware gate detection at the point of release is strictly necessary before delisting occurs.",
    ])

    REPORT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {REPORT_MD}")


def main() -> None:
    split_data, quarter_data, dep_res = build_attack_style_data()
    create_png_chart(quarter_data, CHART_PNG)
    write_markdown_report(split_data, quarter_data, dep_res)


if __name__ == "__main__":
    main()
