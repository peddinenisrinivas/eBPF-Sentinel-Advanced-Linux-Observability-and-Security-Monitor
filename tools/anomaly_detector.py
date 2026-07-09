#!/usr/bin/env python3
"""
tools/anomaly_detector.py
BCC Python loader for anomaly_detector eBPF program.
Detects: privilege escalation, rare syscalls, file storms, fork bombs, new IPs.

Usage:
    sudo python3 tools/anomaly_detector.py [--duration SECS] [--log FILE]
"""

import argparse
import ctypes
import json
import os
import signal
import socket
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from bcc import BPF
except ImportError:
    sys.exit("ERROR: bcc not found. Install: sudo apt install python3-bpfcc")

# ANSI colors
RED, YEL, GRN, CYN = "\033[91m", "\033[93m", "\033[92m", "\033[96m"
BOLD, DIM, RST      = "\033[1m",  "\033[2m",  "\033[0m"
BLK_ON_RED          = "\033[41;97m"

ANOM_PRIVESC       = 1
ANOM_RARE_SYSCALL  = 2
ANOM_FILE_STORM    = 3
ANOM_FORK_BOMB     = 4
ANOM_NEW_DEST_IP   = 5
ANOM_EXEC_MPROTECT = 6

ANOM_INFO = {
    ANOM_PRIVESC:       ("PRIVILEGE ESCALATION", RED,    "🔴"),
    ANOM_RARE_SYSCALL:  ("RARE SYSCALL",         YEL,   "🟡"),
    ANOM_FILE_STORM:    ("FILE OPEN STORM",       YEL,   "🟡"),
    ANOM_FORK_BOMB:     ("FORK BOMB",             RED,   "🔴"),
    ANOM_NEW_DEST_IP:   ("NEW DEST IP",           CYN,   "🔵"),
    ANOM_EXEC_MPROTECT: ("EXEC MPROTECT",         RED,   "🔴"),
}

TASK_COMM_LEN = 16

class Alert(ctypes.Structure):
    _fields_ = [
        ("pid",       ctypes.c_uint32),
        ("uid",       ctypes.c_uint32),
        ("comm",      ctypes.c_char * TASK_COMM_LEN),
        ("anom_type", ctypes.c_uint8),
        ("detail_u32",ctypes.c_uint32),
        ("ts_ns",     ctypes.c_uint64),
        ("extra",     ctypes.c_char * 64),
    ]

def ip4(n): return socket.inet_ntoa(struct.pack("I", n))

# ---------- Args ----------
parser = argparse.ArgumentParser(description="eBPF Anomaly Detector")
parser.add_argument("--duration", type=int,   default=0,    help="Run for N seconds")
parser.add_argument("--log",      type=str,   default=None, help="Write JSON alerts to file")
parser.add_argument("--quiet",    action="store_true",      help="Only show HIGH severity alerts")
args = parser.parse_args()

log_fh = open(args.log, "w") if args.log else None

# ---------- Load eBPF ----------
bpf_src = Path(__file__).parent.parent / "src" / "anomaly_detector.c"
print(f"{BOLD}\n  eBPF Anomaly Detector{RST}")
print(f"{DIM}  Monitoring: privilege escalation, rare syscalls, "
      f"file storms, fork bombs, new IPs{RST}\n")
print(f"  {'TIME':<12} {'SEV':<5} {'TYPE':<26} {'PID':>7} {'UID':>6} {'COMM':<18} DETAIL")
print("  " + "─" * 85)

try:
    b = BPF(src_file=str(bpf_src))
    b.attach_kprobe(event="tcp_v4_connect",   fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect",fn_name="trace_connect_return")
except Exception as e:
    sys.exit(f"Failed to load eBPF program: {e}")

alert_count = 0
start_time  = time.time()

HIGH_SEVERITY = {ANOM_PRIVESC, ANOM_FORK_BOMB, ANOM_EXEC_MPROTECT}

def handle_alert(cpu, data, size):
    global alert_count
    evt = ctypes.cast(data, ctypes.POINTER(Alert)).contents

    if args.quiet and evt.anom_type not in HIGH_SEVERITY:
        return

    alert_count += 1
    ts    = datetime.now().strftime("%H:%M:%S.%f")[:12]
    comm  = evt.comm.decode(errors="replace").strip("\x00")
    extra = evt.extra.decode(errors="replace").strip("\x00")
    name, color, icon = ANOM_INFO.get(evt.anom_type, ("UNKNOWN", YEL, "?"))
    sev   = "HIGH" if evt.anom_type in HIGH_SEVERITY else "MED"
    sev_c = f"{RED}{BOLD}HIGH{RST}" if sev == "HIGH" else f"{YEL}MED{RST}"

    # Format detail field
    detail = extra
    if evt.anom_type == ANOM_NEW_DEST_IP:
        detail = f"dst={ip4(evt.detail_u32)}  {extra}"
    elif evt.anom_type == ANOM_FILE_STORM:
        detail = f"count={evt.detail_u32}/s  {extra}"
    elif evt.anom_type == ANOM_FORK_BOMB:
        detail = f"forks={evt.detail_u32}/s  {extra}"
    elif evt.anom_type == ANOM_RARE_SYSCALL:
        detail = f"arg={evt.detail_u32}  {extra}"

    # Print
    print(f"  {ts:<12} {sev_c:<5} {color}{name:<26}{RST} "
          f"{evt.pid:>7} {evt.uid:>6} {comm:<18} {detail}")

    # Optionally flash a big banner for critical events
    if evt.anom_type in (ANOM_PRIVESC, ANOM_FORK_BOMB):
        print(f"\n  {BLK_ON_RED}  !! {name}: {comm} (pid={evt.pid}) — {detail}  !!  {RST}\n")

    # JSON log
    if log_fh:
        record = {
            "ts": ts, "pid": evt.pid, "uid": evt.uid,
            "comm": comm, "anom_type": name,
            "severity": sev, "detail": detail,
        }
        log_fh.write(json.dumps(record) + "\n")
        log_fh.flush()

b["alerts"].open_perf_buffer(handle_alert, page_cnt=64)

def sig_handler(sig, frame):
    elapsed = time.time() - start_time
    print(f"\n{DIM}  Detected {alert_count} anomalies in {elapsed:.1f}s{RST}")
    if log_fh:
        log_fh.close()
        print(f"{DIM}  Log saved: {args.log}{RST}")
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)

deadline = start_time + args.duration if args.duration else float("inf")
try:
    while time.time() < deadline:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass

sig_handler(None, None)
