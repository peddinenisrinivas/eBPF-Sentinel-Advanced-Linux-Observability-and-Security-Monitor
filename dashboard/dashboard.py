#!/usr/bin/env python3
"""
dashboard/dashboard.py
Live terminal dashboard — combines syscall tracing, CPU profiling,
network monitoring, and anomaly detection into one screen.

Refreshes every 2 seconds using ANSI escape codes (no curses dependency).

Usage:
    sudo python3 dashboard/dashboard.py [--interval 2]
"""

import argparse
import ctypes
import os
import shutil
import signal
import socket
import struct
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

try:
    from bcc import BPF, PerfType, PerfSWConfig
except ImportError:
    sys.exit("ERROR: bcc not found. Install: sudo apt install python3-bpfcc")

# ──────────────────────────────────────────────
# ANSI helpers
# ──────────────────────────────────────────────
ESC = "\033"
def mv(r, c):   return f"{ESC}[{r};{c}H"
def clr():      return f"{ESC}[2J{ESC}[H"
def bold(t):    return f"{ESC}[1m{t}{ESC}[0m"
def dim(t):     return f"{ESC}[2m{t}{ESC}[0m"
def red(t):     return f"{ESC}[91m{t}{ESC}[0m"
def green(t):   return f"{ESC}[92m{t}{ESC}[0m"
def yellow(t):  return f"{ESC}[93m{t}{ESC}[0m"
def cyan(t):    return f"{ESC}[96m{t}{ESC}[0m"
def magenta(t): return f"{ESC}[95m{t}{ESC}[0m"

def hide_cursor(): sys.stdout.write(f"{ESC}[?25l")
def show_cursor(): sys.stdout.write(f"{ESC}[?25h")

def bar(pct, width=20, fill="█", empty="░"):
    n = int(min(pct, 100) / 100 * width)
    return fill * n + empty * (width - n)

def fmt_bytes(b):
    if b < 1024:        return f"{b}B"
    if b < 1_048_576:   return f"{b/1024:.1f}K"
    if b < 1_073_741_824: return f"{b/1048576:.1f}M"
    return f"{b/1073741824:.1f}G"

def ip4(n): return socket.inet_ntoa(struct.pack("I", n))

# ──────────────────────────────────────────────
# ctypes event structures
# ──────────────────────────────────────────────
TASK_COMM_LEN = 16

class SyscallEvent(ctypes.Structure):
    _fields_ = [
        ("pid",        ctypes.c_uint32),
        ("uid",        ctypes.c_uint32),
        ("comm",       ctypes.c_char * TASK_COMM_LEN),
        ("fname",      ctypes.c_char * 256),
        ("ret",        ctypes.c_int32),
        ("ts_ns",      ctypes.c_uint64),
        ("syscall_id", ctypes.c_uint8),
    ]

class NetEvent(ctypes.Structure):
    _fields_ = [
        ("pid",        ctypes.c_uint32),
        ("uid",        ctypes.c_uint32),
        ("comm",       ctypes.c_char * TASK_COMM_LEN),
        ("saddr",      ctypes.c_uint32),
        ("daddr",      ctypes.c_uint32),
        ("sport",      ctypes.c_uint16),
        ("dport",      ctypes.c_uint16),
        ("bytes",      ctypes.c_uint64),
        ("ts_ns",      ctypes.c_uint64),
        ("event_type", ctypes.c_uint8),
    ]

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

# ──────────────────────────────────────────────
# State shared across callbacks and render loop
# ──────────────────────────────────────────────
SYSCALL_NAMES   = {0: "openat", 1: "execve", 2: "read", 3: "write"}
ANOM_NAMES      = {1:"PRIVESC", 2:"RARE_SC", 3:"FILE_STORM", 4:"FORKBOMB", 5:"NEW_IP", 6:"EXEC_MPR"}
HIGH_SEV        = {1, 4, 6}

state = {
    "sc_events":  deque(maxlen=8),    # recent syscall events
    "net_events": deque(maxlen=8),    # recent network events
    "alerts":     deque(maxlen=6),    # recent anomaly alerts
    "tx_total":   defaultdict(int),   # pid -> bytes
    "rx_total":   defaultdict(int),
    "sc_counts":  defaultdict(int),   # syscall_id -> count
    "net_conns":  0,
    "alert_count":0,
}

src_dir = Path(__file__).parent.parent / "src"

# ──────────────────────────────────────────────
# Inline eBPF source (all three modules merged)
# We load them from src/ files; fall back to inline stubs if files missing.
# ──────────────────────────────────────────────
def load_source(fname):
    p = src_dir / fname
    if p.exists():
        return p.read_text()
    return ""

# We load each module separately via individual BPF instances
# (BCC limitation: one perf output per name)
bpfs = {}

def load_bpf(name, fname, extra_attach=None):
    src = load_source(fname)
    if not src:
        print(f"[warn] {fname} not found, skipping {name}")
        return None
    try:
        b = BPF(text=src)
        if extra_attach: extra_attach(b)
        bpfs[name] = b
        return b
    except Exception as e:
        print(f"[warn] Failed to load {name}: {e}")
        return None

# ──────────────────────────────────────────────
# Callbacks
# ──────────────────────────────────────────────
def cb_syscall(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(SyscallEvent)).contents
    ts  = datetime.now().strftime("%H:%M:%S")
    comm= evt.comm.decode(errors="replace").strip("\x00")
    fname=evt.fname.decode(errors="replace").strip("\x00")[:40]
    sc  = SYSCALL_NAMES.get(evt.syscall_id, "?")
    state["sc_events"].append((ts, evt.pid, comm, sc, fname, evt.ret))
    state["sc_counts"][evt.syscall_id] += 1

def cb_net(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(NetEvent)).contents
    ts  = datetime.now().strftime("%H:%M:%S")
    comm= evt.comm.decode(errors="replace").strip("\x00")
    dst = f"{ip4(evt.daddr)}:{socket.ntohs(evt.dport)}"
    state["net_events"].append((ts, evt.pid, comm, evt.event_type, dst, evt.bytes))
    state["tx_total"][evt.pid] += evt.bytes if evt.event_type == 4 else 0
    state["rx_total"][evt.pid] += evt.bytes if evt.event_type == 5 else 0
    if evt.event_type in (1, 2): state["net_conns"] += 1

def cb_alert(cpu, data, size):
    evt  = ctypes.cast(data, ctypes.POINTER(Alert)).contents
    ts   = datetime.now().strftime("%H:%M:%S")
    comm = evt.comm.decode(errors="replace").strip("\x00")
    extra= evt.extra.decode(errors="replace").strip("\x00")
    name = ANOM_NAMES.get(evt.anom_type, "UNKNOWN")
    detail = extra
    if evt.anom_type == 5: detail = f"dst={ip4(evt.detail_u32)}"
    state["alerts"].append((ts, evt.pid, comm, name, detail, evt.anom_type in HIGH_SEV))
    state["alert_count"] += 1

# ──────────────────────────────────────────────
# Render
# ──────────────────────────────────────────────
EVT_TYPE_LABEL = {1:"CONNECT", 2:"ACCEPT", 3:"CLOSE", 4:"SEND", 5:"RECV"}

def render(width, start_time):
    lines = []
    W = width

    def sep(ch="─"):
        lines.append(dim("  " + ch * (W - 4)))

    elapsed = int(time.time() - start_time)
    ts_now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title   = f"  eBPF Performance Tool  │  {ts_now}  │  uptime {elapsed}s"
    lines.append(bold(cyan(title)))
    sep("═")

    # ── Syscall summary ──
    lines.append(bold("  SYSCALL ACTIVITY"))
    sc_total = sum(state["sc_counts"].values())
    for sid, name in SYSCALL_NAMES.items():
        cnt  = state["sc_counts"][sid]
        pct  = cnt / sc_total * 100 if sc_total else 0
        b20  = bar(pct, 16)
        lines.append(f"    {name:<8}  {b20}  {cnt:>6}")
    sep()

    # ── Recent syscalls ──
    lines.append(bold("  RECENT SYSCALLS"))
    lines.append(dim(f"    {'TIME':<10} {'PID':>7} {'COMM':<16} {'CALL':<10} {'RET':>5}  FILE"))
    for ts, pid, comm, sc, fname, ret in reversed(list(state["sc_events"])):
        ret_s = red(str(ret)) if ret < 0 else dim(str(ret))
        lines.append(f"    {ts:<10} {pid:>7} {comm:<16} {sc:<10} {ret_s:>5}  {dim(fname)}")
    sep()

    # ── Network ──
    lines.append(bold(f"  NETWORK  │  connections seen: {state['net_conns']}"))
    lines.append(dim(f"    {'TIME':<10} {'PID':>7} {'COMM':<16} {'TYPE':<10} {'DST':<24} {'BYTES':>8}"))
    for ts, pid, comm, etype, dst, byt in reversed(list(state["net_events"])):
        elabel = EVT_TYPE_LABEL.get(etype, "?")
        ec = cyan if etype == 1 else (green if etype == 2 else dim)
        bstr = fmt_bytes(byt) if byt else ""
        lines.append(f"    {ts:<10} {pid:>7} {comm:<16} {ec(elabel):<10} {dst:<24} {bstr:>8}")
    sep()

    # ── Anomaly alerts ──
    alert_hdr = bold(f"  ANOMALY ALERTS  │  total: {state['alert_count']}")
    lines.append(alert_hdr)
    if not state["alerts"]:
        lines.append(dim("    No anomalies detected."))
    for ts, pid, comm, name, detail, is_high in reversed(list(state["alerts"])):
        sev_s = red(bold("HIGH")) if is_high else yellow("MED ")
        lines.append(f"    {ts:<10} {sev_s}  {red(name) if is_high else yellow(name):<14} "
                     f"pid={pid:<7} {comm:<16} {detail}")
    sep("═")
    lines.append(dim("  Press Ctrl-C to exit"))

    output = clr() + "\n".join(lines)
    sys.stdout.write(output)
    sys.stdout.flush()

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
parser = argparse.ArgumentParser(description="eBPF Live Dashboard")
parser.add_argument("--interval", type=float, default=2.0, help="Refresh interval seconds")
args = parser.parse_args()

print("Loading eBPF programs...")

b_sc = load_bpf("syscall", "syscall_tracer.c")
b_net= load_bpf("network", "network_monitor.c", lambda b: (
    b.attach_kprobe(event="tcp_v4_connect",    fn_name="trace_connect_entry"),
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return"),
    b.attach_kretprobe(event="inet_csk_accept",fn_name="trace_accept_return"),
    b.attach_kprobe(event="tcp_sendmsg",       fn_name="trace_tcp_sendmsg"),
    b.attach_kprobe(event="tcp_recvmsg",       fn_name="trace_tcp_recvmsg"),
    b.attach_kretprobe(event="tcp_recvmsg",    fn_name="trace_tcp_recvmsg_return"),
))
b_ad = load_bpf("anomaly", "anomaly_detector.c", lambda b: (
    b.attach_kprobe(event="tcp_v4_connect",    fn_name="trace_connect_entry"),
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return"),
))

if b_sc:  b_sc["events"].open_perf_buffer(cb_syscall,  page_cnt=64)
if b_net: b_net["net_events"].open_perf_buffer(cb_net, page_cnt=128)
if b_ad:  b_ad["alerts"].open_perf_buffer(cb_alert,    page_cnt=32)

start_time = time.time()
hide_cursor()

def cleanup(sig=None, frame=None):
    show_cursor()
    print(clr())
    print(bold("Dashboard stopped."))
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

width = shutil.get_terminal_size((120, 40)).columns

try:
    while True:
        for b in bpfs.values():
            try: b.perf_buffer_poll(timeout=50)
            except: pass
        render(width, start_time)
        time.sleep(args.interval)
except Exception as e:
    cleanup()
    raise
