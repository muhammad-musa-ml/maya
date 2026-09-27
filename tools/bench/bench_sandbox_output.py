"""Measure parent memory while a sandbox child writes increasing output.

The baseline reproduces the previous ``subprocess.run(capture_output=True)``
transport; the bounded transport is the current implementation. This measures
the parent Python heap with tracemalloc, not child memory or total RSS.

Usage: python tools/bench/bench_sandbox_output.py [output directory]
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from maya.security.sandbox import _child_env, _run_capped  # noqa: E402

CAP = 2 * 1024 * 1024
SIZES_MB = (1, 4, 16, 32)


def measure(size_mb: int, bounded: bool, cwd: str) -> dict[str, float | int | str]:
    blocks = size_mb * 16  # 64 KiB per block
    code = f"import os\nfor _ in range({blocks}): os.write(1, b'x' * 65536)"
    argv = [sys.executable, "-I", "-c", code]
    tracemalloc.start()
    started = time.perf_counter()
    if bounded:
        out, _, _, reason = _run_capped(argv, "", cwd, _child_env(), 30, CAP)
    else:
        proc = subprocess.run(
            argv, capture_output=True, check=False, cwd=cwd, env=_child_env(), timeout=30
        )
        out, reason = proc.stdout, "completed"
    seconds = time.perf_counter() - started
    peak_bytes = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return {
        "child_output_mb": size_mb,
        "transport": "bounded" if bounded else "previous_capture_output",
        "parent_python_peak_mb": round(peak_bytes / 1048576, 3),
        "retained_output_mb": round(len(out) / 1048576, 3),
        "elapsed_seconds": round(seconds, 3),
        "termination": reason,
    }


def chart(rows: list[dict[str, float | int | str]]) -> str:
    max_peak = max(float(row["parent_python_peak_mb"]) for row in rows)
    colors = {"previous_capture_output": "#a84331", "bounded": "#137b77"}
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="860" height="430" viewBox="0 0 860 430">',
        '<rect width="860" height="430" fill="#fff"/>',
        '<text x="54" y="33" font-size="20" font-family="sans-serif">Sandbox output: parent Python peak memory</text>',
        f'<text x="54" y="56" font-size="12" font-family="sans-serif">{platform.system()}, 2 MiB output cap; tracemalloc, one run per point</text>',
    ]
    left, top, width, height = 72, 85, 720, 275
    for tick in range(5):
        y = top + height - tick * height / 4
        value = max_peak * tick / 4
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + width}" y2="{y:.1f}" stroke="#ddd"/>')
        parts.append(f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" font-size="11" font-family="sans-serif">{value:.0f}</text>')
    for i, size in enumerate(SIZES_MB):
        center = left + width * (i + 0.5) / len(SIZES_MB)
        for j, mode in enumerate(("previous_capture_output", "bounded")):
            row = next(r for r in rows if r["child_output_mb"] == size and r["transport"] == mode)
            value = float(row["parent_python_peak_mb"])
            bar_h = height * value / max_peak
            x = center - 35 + 36 * j
            y = top + height - bar_h
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="30" height="{bar_h:.1f}" fill="{colors[mode]}"/>')
            parts.append(f'<text x="{x + 15:.1f}" y="{y - 5:.1f}" text-anchor="middle" font-size="10" font-family="sans-serif">{value:.1f}</text>')
        parts.append(f'<text x="{center:.1f}" y="382" text-anchor="middle" font-size="12" font-family="sans-serif">{size} MiB</text>')
    parts += [
        '<rect x="530" y="400" width="12" height="12" fill="#a84331"/><text x="548" y="411" font-size="11" font-family="sans-serif">Previous capture</text>',
        '<rect x="680" y="400" width="12" height="12" fill="#137b77"/><text x="698" y="411" font-size="11" font-family="sans-serif">Bounded drain</text>',
        '</svg>',
    ]
    return "\n".join(parts)


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "benchmarks"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="maya-bench-sandbox-") as cwd:
        rows = [measure(size, bounded, cwd) for size in SIZES_MB for bounded in (False, True)]
    result = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cap_mb": CAP / 1048576,
        "method": "tracemalloc peak of parent Python allocations; one run per point",
        "measurements": rows,
    }
    (output / "sandbox-output.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (output / "sandbox-output.svg").write_text(chart(rows), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
