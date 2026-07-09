#!/usr/bin/env python3
"""
tools/cpu_profiler.py
BCC Python loader for cpu_profiler eBPF program.
Shows:
  - Run-queue latency histogram (log2 scale in nanoseconds)
  - Top processes by on-CPU and off-CPU time
  - CPU sample counts (for basic flame-graph data)

Usage:
    sudo python3 tools/cpu_profiler.py [--duration 30] [--interval 5]
"""

import argparse
import ctypes
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from bcc import BPF, PerfType, PerfSWConfig
except ImportError:
    sys.exit("ERROR: bcc not found. Install: sudo apt install python3-bpfcc")

COLORS = {
    "red":   "\033[91m", "green":  "\033[92m",
    "yellow":"\033[93m", "cyan":   "\033[96m",
    "bold":  "\033[1m",  "reset":  "\033[0m",
    "dim":   "\033[2m",
}
def c(col, txt): return f"{COLORS[col]}{txt}{COLORS['reset']}"

# ---------- Args ----------
parser = argparse.ArgumentParser(description="eBPF CPU Profiler")
parser.add_argument("--duration", type=int, default=30,  help="Total run time in seconds")
parser.add_argument("--interval", type=int, default=5,   help="Report interval in seconds")
parser.add_argument("--top",      type=int, default=15,  help="Top N processes to show")
args = parser.parse_args()

# ---------- Load eBPF ----------
bpf_src = Path(__file__).parent.parent / "src" / "cpu_profiler.c"
print(c("bold", "\n  eBPF CPU Profiler"))
print(c("dim",  f"  Duration: {args.duration}s  |  Interval: {args.interval}s\n"))

try:
    b = BPF(src_file=str(bpf_src))
except Exception as e:
    sys.exit(f"Failed to load eBPF program: {e}")

# Attach scheduler raw tracepoints (already attached via RAW_TRACEPOINT_PROBE)
# Attach perf sampling at 99 Hz for CPU flamegraph data
try:
    b.attach_perf_event(
        ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK,
        fn_name="do_perf_event",
        sample_freq=99,
    )
    perf_attached = True
except Exception as e:
    print(c("yellow", f"  [warn] perf sampling not attached: {e}"))
    perf_attached = False

# ---------- Display helpers ----------
NS = 1_000_000_000

def fmt_ns(ns):
    if ns < 1_000:        return f"{ns}ns"
    if ns < 1_000_000:    return f"{ns/1e3:.1f}µs"
    if ns < 1_000_000_000:return f"{ns/1e6:.1f}ms"
    return f"{ns/1e9:.2f}s"

def print_histogram(b):
    print(c("bold", "\n  Run-queue latency histogram (time spent waiting for CPU)"))
    print(c("dim",  "  Each row = log2(nanoseconds) bucket\n"))
    b["runq_lat"].print_log2_hist("nsecs", "RQ Latency")

def print_cpu_times(b):
    print(c("bold", f"\n  Top {args.top} processes — CPU time"))
    print(f"  {'PID':>8}  {'ON-CPU':>12}  {'OFF-CPU':>12}  {'% ON':>7}")
    print("  " + "─" * 46)

    pids = set()
    for k in b["oncpu_ns"].keys():  pids.add(k.value)
    for k in b["offcpu_ns"].keys(): pids.add(k.value)

    rows = []
    for pid in pids:
        on  = b["oncpu_ns"].get( ctypes.c_uint32(pid), ctypes.c_uint64(0)).value
        off = b["offcpu_ns"].get(ctypes.c_uint32(pid), ctypes.c_uint64(0)).value
        total = on + off
        pct = (on / total * 100) if total > 0 else 0
        rows.append((pid, on, off, pct))
    rows.sort(key=lambda x: x[1], reverse=True)

    for pid, on, off, pct in rows[:args.top]:
        bar_w = int(pct / 5)
        bar   = "█" * bar_w + "░" * (20 - bar_w)
        pct_c = c("green", f"{pct:6.1f}%") if pct > 50 else c("yellow", f"{pct:6.1f}%")
        print(f"  {pid:>8}  {fmt_ns(on):>12}  {fmt_ns(off):>12}  {pct_c}  {bar}")

def print_cpu_samples(b):
    if not perf_attached: return
    print(c("bold", f"\n  Top {args.top} processes — CPU samples (99 Hz)"))
    print(f"  {'PID':>8}  {'COMM':<18}  {'SAMPLES':>8}  CPU%")
    print("  " + "─" * 50)

    rows = [(k.pid, k.comm.decode(errors="replace"), v.value)
            for k, v in b["counts"].items()]
    rows.sort(key=lambda x: x[2], reverse=True)
    total = sum(r[2] for r in rows) or 1

    for pid, comm, samp in rows[:args.top]:
        pct  = samp / total * 100
        bar  = "█" * int(pct / 2)
        print(f"  {pid:>8}  {comm:<18}  {samp:>8}  {pct:5.1f}%  {bar}")

# ---------- Main loop ----------
deadline = time.time() + args.duration
next_report = time.time() + args.interval

def sig_handler(sig, frame):
    print_histogram(b)
    print_cpu_times(b)
    print_cpu_samples(b)
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)

print(c("dim", f"  Profiling for {args.duration} seconds... (Ctrl-C to stop early)\n"))

while time.time() < deadline:
    remaining = min(next_report, deadline) - time.time()
    if remaining > 0:
        time.sleep(remaining)

    ts = datetime.now().strftime("%H:%M:%S")
    print(c("cyan", f"\n  ─── Report @ {ts} ───"))
    print_cpu_times(b)
    print_cpu_samples(b)
    next_report += args.interval

print_histogram(b)
print(c("bold", "\n  Profiling complete.\n"))
