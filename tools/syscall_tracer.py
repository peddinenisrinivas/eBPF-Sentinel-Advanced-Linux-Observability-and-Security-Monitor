#!/usr/bin/env python3
"""
tools/syscall_tracer.py
BCC Python loader for the syscall_tracer eBPF program.
Traces open(), execve(), read(), write() in real time.

Usage:
    sudo python3 tools/syscall_tracer.py [--pid PID] [--comm COMM] [--duration SECS]
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
    from bcc import BPF
except ImportError:
    sys.exit("ERROR: bcc not found. Install: sudo apt install python3-bpfcc")

# ---------- Constants ----------
SYSCALL_NAMES = {0: "openat", 1: "execve", 2: "read", 3: "write"}
COLORS = {
    "red":    "\033[91m", "green":  "\033[92m",
    "yellow": "\033[93m", "cyan":   "\033[96m",
    "bold":   "\033[1m",  "reset":  "\033[0m",
    "dim":    "\033[2m",
}

def c(color, text):
    return f"{COLORS[color]}{text}{COLORS['reset']}"

# ---------- ctypes mirror of event_t ----------
TASK_COMM_LEN = 16

class Event(ctypes.Structure):
    _fields_ = [
        ("pid",        ctypes.c_uint32),
        ("uid",        ctypes.c_uint32),
        ("comm",       ctypes.c_char * TASK_COMM_LEN),
        ("fname",      ctypes.c_char * 256),
        ("ret",        ctypes.c_int32),
        ("ts_ns",      ctypes.c_uint64),
        ("syscall_id", ctypes.c_uint8),
    ]

# ---------- Argument parsing ----------
parser = argparse.ArgumentParser(description="eBPF Syscall Tracer")
parser.add_argument("--pid",      type=int,   default=None, help="Filter by PID")
parser.add_argument("--comm",     type=str,   default=None, help="Filter by process name")
parser.add_argument("--duration", type=int,   default=0,    help="Stop after N seconds (0=forever)")
parser.add_argument("--failed",   action="store_true",      help="Show only failed calls")
args = parser.parse_args()

# ---------- Load eBPF program ----------
bpf_src_path = Path(__file__).parent.parent / "src" / "syscall_tracer.c"

print(c("bold", "\n  eBPF Syscall Tracer"))
print(c("dim",  "  Tracing open, execve, read, write system calls\n"))
print(f"  {'TIME':<12} {'PID':>7} {'UID':>6} {'COMM':<18} {'SYSCALL':<10} {'RET':>6}  FILE/ARG")
print("  " + "─" * 80)

try:
    b = BPF(src_file=str(bpf_src_path))
except Exception as e:
    sys.exit(f"Failed to load eBPF program: {e}")

# ---------- Event callback ----------
event_count = 0
start_time  = time.time()

def handle_event(cpu, data, size):
    global event_count
    evt = ctypes.cast(data, ctypes.POINTER(Event)).contents

    # Apply filters
    if args.pid  and evt.pid  != args.pid:  return
    if args.comm and args.comm not in evt.comm.decode(errors="replace"): return
    if args.failed and evt.ret >= 0: return

    event_count += 1
    ts   = datetime.now().strftime("%H:%M:%S.%f")[:12]
    comm = evt.comm.decode(errors="replace").strip("\x00")
    fname= evt.fname.decode(errors="replace").strip("\x00")
    sc   = SYSCALL_NAMES.get(evt.syscall_id, "?")
    ret_str = c("red", str(evt.ret)) if evt.ret < 0 else str(evt.ret)

    sc_color = {"openat": "cyan", "execve": "green",
                "read": "dim", "write": "dim"}.get(sc, "reset")

    print(f"  {ts:<12} {evt.pid:>7} {evt.uid:>6} {comm:<18} "
          f"{c(sc_color, sc):<10}  {ret_str:>6}  {fname[:60]}")

# Open the perf buffer
b["events"].open_perf_buffer(handle_event, page_cnt=64)

# ---------- Statistics loop ----------
def print_io_stats(b):
    print(c("bold", "\n  Top processes by I/O bytes:"))
    print(f"  {'PID':>8}  {'READ bytes':>14}  {'WRITE bytes':>14}")
    print("  " + "─" * 42)

    pids = set()
    for pid, _ in b["read_bytes"].items():  pids.add(pid.value)
    for pid, _ in b["write_bytes"].items(): pids.add(pid.value)

    rows = []
    for pid in pids:
        rb = b["read_bytes"].get(ctypes.c_uint32(pid), ctypes.c_uint64(0)).value
        wb = b["write_bytes"].get(ctypes.c_uint32(pid), ctypes.c_uint64(0)).value
        rows.append((pid, rb, wb))
    rows.sort(key=lambda x: x[1]+x[2], reverse=True)

    for pid, rb, wb in rows[:10]:
        print(f"  {pid:>8}  {rb:>14,}  {wb:>14,}")

# ---------- Signal handler ----------
def sig_handler(sig, frame):
    print_io_stats(b)
    print(c("dim", f"\n  Captured {event_count} events in "
            f"{time.time()-start_time:.1f}s"))
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)

# ---------- Poll loop ----------
deadline = start_time + args.duration if args.duration else float("inf")
try:
    while time.time() < deadline:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass

if args.duration:
    print_io_stats(b)
    print(c("dim", f"\n  Duration reached. {event_count} events captured."))
