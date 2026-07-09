#!/usr/bin/env python3
"""
tools/network_monitor.py
BCC Python loader for network_monitor eBPF program.
Shows TCP connect/accept events, send/recv bytes per process.

Usage:
    sudo python3 tools/network_monitor.py [--duration SECS]
"""

import argparse
import ctypes
import signal
import socket
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from bcc import BPF
except ImportError:
    sys.exit("ERROR: bcc not found. Install: sudo apt install python3-bpfcc")

COLORS = {
    "red":   "\033[91m", "green":  "\033[92m",
    "yellow":"\033[93m", "cyan":   "\033[96m",
    "bold":  "\033[1m",  "reset":  "\033[0m",
    "dim":   "\033[2m",
}
def c(col, txt): return f"{COLORS[col]}{txt}{COLORS['reset']}"

EVT_CONNECT, EVT_ACCEPT, EVT_CLOSE, EVT_SEND, EVT_RECV = 1, 2, 3, 4, 5
EVT_LABELS = {
    EVT_CONNECT: ("CONNECT", "green"),
    EVT_ACCEPT:  ("ACCEPT",  "cyan"),
    EVT_CLOSE:   ("CLOSE",   "dim"),
    EVT_SEND:    ("SEND",    "yellow"),
    EVT_RECV:    ("RECV",    "dim"),
}

TASK_COMM_LEN = 16

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

def ip4(n):
    return socket.inet_ntoa(struct.pack("I", n))

def fmt_bytes(b):
    if b < 1024:       return f"{b}B"
    if b < 1048576:    return f"{b/1024:.1f}KB"
    return f"{b/1048576:.1f}MB"

# ---------- Args ----------
parser = argparse.ArgumentParser(description="eBPF Network Monitor")
parser.add_argument("--duration", type=int, default=0, help="Stop after N seconds")
parser.add_argument("--no-send-recv", action="store_true", help="Hide high-volume send/recv events")
args = parser.parse_args()

# ---------- Load eBPF ----------
bpf_src = Path(__file__).parent.parent / "src" / "network_monitor.c"
print(c("bold", "\n  eBPF Network Monitor"))
print(c("dim",  "  Tracing TCP connect, accept, send, recv\n"))
print(f"  {'TIME':<12} {'PID':>7} {'COMM':<18} {'EVENT':<10} {'SRC':<22} {'DST':<22} {'BYTES':>10}")
print("  " + "─" * 90)

try:
    b = BPF(src_file=str(bpf_src))
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")
    b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
    b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg")
    b.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg_return")
except Exception as e:
    sys.exit(f"Failed to load eBPF program: {e}")

# ---------- Connection tracking ----------
conn_count  = defaultdict(int)   # daddr -> connection count
start_time  = time.time()
event_count = 0

def handle_event(cpu, data, size):
    global event_count
    evt = ctypes.cast(data, ctypes.POINTER(NetEvent)).contents

    if args.no_send_recv and evt.event_type in (EVT_SEND, EVT_RECV):
        return

    event_count += 1
    ts   = datetime.now().strftime("%H:%M:%S.%f")[:12]
    comm = evt.comm.decode(errors="replace").strip("\x00")

    src = f"{ip4(evt.saddr)}:{socket.ntohs(evt.sport)}"
    dst = f"{ip4(evt.daddr)}:{socket.ntohs(evt.dport)}"

    label, color = EVT_LABELS.get(evt.event_type, ("?", "reset"))
    bstr = fmt_bytes(evt.bytes) if evt.bytes > 0 else ""

    if evt.event_type == EVT_CONNECT:
        conn_count[evt.daddr] += 1

    print(f"  {ts:<12} {evt.pid:>7} {comm:<18} "
          f"{c(color, label):<10} {src:<22} {dst:<22} {bstr:>10}")

b["net_events"].open_perf_buffer(handle_event, page_cnt=128)

def print_summary(b):
    print(c("bold", "\n\n  Network I/O summary by process:"))
    print(f"  {'PID':>8}  {'TX':>12}  {'RX':>12}")
    print("  " + "─" * 38)

    pids = set()
    for k in b["tx_bytes"].keys(): pids.add(k.value)
    for k in b["rx_bytes"].keys(): pids.add(k.value)

    rows = []
    for pid in pids:
        tx = b["tx_bytes"].get(ctypes.c_uint32(pid), ctypes.c_uint64(0)).value
        rx = b["rx_bytes"].get(ctypes.c_uint32(pid), ctypes.c_uint64(0)).value
        rows.append((pid, tx, rx))
    rows.sort(key=lambda x: x[1]+x[2], reverse=True)
    for pid, tx, rx in rows[:15]:
        print(f"  {pid:>8}  {fmt_bytes(tx):>12}  {fmt_bytes(rx):>12}")

    print(c("dim", f"\n  {event_count} events in {time.time()-start_time:.1f}s"))

def sig_handler(sig, frame):
    print_summary(b)
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)

deadline = start_time + args.duration if args.duration else float("inf")
try:
    while time.time() < deadline:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass

print_summary(b)
