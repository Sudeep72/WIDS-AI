"""Benchmark full pipeline throughput and peak process memory."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wids_ai.pipeline import analyze_pcap  # noqa: E402


def peak_memory_mb() -> float | None:
    """Return peak resident memory in MiB when the platform exposes it."""
    try:
        import resource
    except ImportError:
        resource = None
    if resource is not None:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return value / (1024 * 1024) if value > 1024 * 1024 else value / 1024
    try:
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        process = kernel32.GetCurrentProcess()
        success = psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb)
        if success:
            return counters.PeakWorkingSetSize / (1024 * 1024)
    except (AttributeError, OSError, ValueError):
        return None
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, default=Path("data/synthetic/benign_baseline.pcap"))
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args(argv)
    if args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")
    durations: list[float] = []
    frames = 0
    for _ in range(args.repeat):
        started = time.perf_counter()
        result = analyze_pcap(args.pcap, use_ml=False)
        durations.append(time.perf_counter() - started)
        frames = result.frame_count
    best = min(durations)
    print(f"PCAP: {args.pcap}")
    print(f"Frames: {frames}")
    print(f"Frames per second: {frames / best:.2f}")
    print(f"Best seconds: {best:.3f}")
    peak = peak_memory_mb()
    print(f"Peak memory MB: {peak:.2f}" if peak is not None else "Peak memory MB: unavailable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
