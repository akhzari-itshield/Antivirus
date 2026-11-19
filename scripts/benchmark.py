#!/usr/bin/env python3
"""ITShield Antivirus - Scan performance benchmark.

Measures the scanner's throughput on a set of files and reports:
    * files per second
    * bytes per second
    * average time per file
    * memory usage before/after

Usage:
    python3 scripts/benchmark.py /path/to/scan
    python3 scripts/benchmark.py /path/to/scan --iterations 3
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import tracemalloc
from pathlib import Path

# Ensure the project root is importable.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from itshield.config.settings import reload_settings
from itshield.scanner.file_analyzer import FileAnalyzer
from itshield.scanner.hash_engine import HashEngine
from itshield.scanner.models import ScanRequest
from itshield.scanner.scanner import FileScanner
from itshield.scanner.signature_engine import SignatureEngine
from itshield.scanner.yara_engine import YaraEngine


def run_benchmark(target: Path, iterations: int = 1) -> None:
    """Run the benchmark on ``target``."""
    reload_settings()

    scanner = FileScanner(
        hash_engine=HashEngine(),
        signature_engine=SignatureEngine(),
        yara_engine=YaraEngine(),
        analyzer=FileAnalyzer(),
    )

    # Count files first.
    file_list = list(scanner._iter_files(target))
    total_files = len(file_list)
    total_bytes = sum(f.stat().st_size for f in file_list if f.exists())

    print(f"ITShield Antivirus - Scan Benchmark")
    print(f"=" * 60)
    print(f"Target:          {target}")
    print(f"Files:           {total_files}")
    print(f"Total bytes:     {total_bytes:,} ({total_bytes / (1024*1024):.1f} MiB)")
    print(f"Iterations:      {iterations}")
    print(f"Hash engine:     {scanner.hash_engine.backend}")
    print(f"YARA rules:      {scanner.yara_engine.rule_count}")
    print(f"Signatures:      {len(scanner.signature_engine)}")
    print()

    for i in range(iterations):
        print(f"--- Iteration {i+1}/{iterations} ---")

        tracemalloc.start()
        start = time.time()
        request = ScanRequest.from_path(target)
        stats = scanner.scan(request)
        elapsed = time.time() - start

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        files_per_sec = stats.files_scanned / elapsed if elapsed > 0 else 0
        bytes_per_sec = total_bytes / elapsed if elapsed > 0 else 0
        avg_per_file = (elapsed / stats.files_scanned * 1000) if stats.files_scanned > 0 else 0

        print(f"  Duration:        {elapsed:.3f}s")
        print(f"  Files/sec:       {files_per_sec:.1f}")
        print(f"  Bytes/sec:       {bytes_per_sec:,.0f} ({bytes_per_sec/(1024*1024):.1f} MiB/s)")
        print(f"  Avg per file:    {avg_per_file:.2f}ms")
        print(f"  Memory (peak):   {peak / (1024*1024):.1f} MiB")
        print(f"  Results:         clean={stats.files_clean} susp={stats.files_suspicious} "
              f"malic={stats.files_malicious} skipped={stats.files_skipped}")
        print()

    print("=" * 60)
    print("Benchmark complete.")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="benchmark",
        description="ITShield Antivirus scan performance benchmark",
    )
    parser.add_argument("target", help="Directory or file to benchmark-scan.")
    parser.add_argument(
        "--iterations", "-n", type=int, default=1,
        help="Number of iterations to run (default: 1).",
    )
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        return 1

    run_benchmark(target, iterations=args.iterations)
    return 0


if __name__ == "__main__":
    sys.exit(main())
