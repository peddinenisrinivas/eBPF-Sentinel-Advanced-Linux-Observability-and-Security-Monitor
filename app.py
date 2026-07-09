import os
import sys
import time
import ctypes
import socket
import struct
import traceback
from datetime import datetime
from pathlib import Path
from collections import deque, defaultdict

from flask import Flask, render_template, jsonify

try:
    from bcc import BPF
except ImportError:
    sys.exit("ERROR: bcc not found. Install: sudo apt install python3-bpfcc")

# --- Configuration ---
SRC_DIR = Path(__file__).parent / "src"
UI_DIR = Path(__file__).parent / "dashboard" / "ui"

app = Flask(__name__, static_folder=str(UI_DIR), static_url_path='/static', template_folder=str(UI_DIR))

# --- BPF Structures (Sync with src/*.c) ---
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


# --- Helpers ---
def ip4(n): return socket.inet_ntoa(struct.pack("I", n))

SYSCALL_NAMES = {0: "openat", 1: "execve", 2: "read", 3: "write"}
ANOM_NAMES    = {1:"PRIVESC", 2:"RARE_SC", 3:"FILE_STORM", 4:"FORKBOMB", 5:"NEW_IP", 6:"EXEC_MPROTECT"}

NET_EVT_LABELS= {1:"CONNECT", 2:"ACCEPT", 3:"CLOSE", 4:"SEND", 5:"RECV"}

# --- Shared State (thread-safe via GIL) ---
state = {
    "sc_events":  deque(maxlen=100),
    "net_events": deque(maxlen=100),
    "alerts":     deque(maxlen=50),
    "sc_counts":  defaultdict(int),
    "net_conns":  0,
    "alert_count": 0,
    "cpu_hist":   [0] * 64,
    "top_net_tx": [],
    "worker_status": "starting",
    "worker_error": None,
    "loaded_modules": [],
}

# --- BPF Logic ---
bpfs = {}

def load_bpf(name, fname, extra_attach=None):
    p = SRC_DIR / fname
    if not p.exists():
        msg = f"[warn] {fname} not found at {p}"
        print(msg, flush=True)
        return None
    try:
        print(f"[...] Loading {name} from {p}...", flush=True)
        src = p.read_text()
        b = BPF(text=src)
        if extra_attach:
            extra_attach(b)
        bpfs[name] = b
        state["loaded_modules"].append(name)
        print(f"[OK] {name} loaded successfully", flush=True)
        return b

    except Exception as e:
        msg = f"[err] Failed to load {name}: {e}"
        print(msg, flush=True)
        traceback.print_exc()
        return None

# --- Callbacks ---
def cb_syscall(cpu, data, size):
    try:
        evt = ctypes.cast(data, ctypes.POINTER(SyscallEvent)).contents
        payload = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "pid": evt.pid,
            "comm": evt.comm.decode(errors="replace").strip("\x00"),
            "syscall": SYSCALL_NAMES.get(evt.syscall_id, "?"),
            "fname": evt.fname.decode(errors="replace").strip("\x00"),
            "ret": evt.ret
        }
        state["sc_events"].append(payload)
        state["sc_counts"][evt.syscall_id] += 1
    except Exception as e:
        print(f"[cb_syscall error] {e}", flush=True)

def cb_net(cpu, data, size):
    try:
        evt = ctypes.cast(data, ctypes.POINTER(NetEvent)).contents
        payload = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "pid": evt.pid,
            "comm": evt.comm.decode(errors="replace").strip("\x00"),
            "type": NET_EVT_LABELS.get(evt.event_type, "?"),
            "dst": f"{ip4(evt.daddr)}:{socket.ntohs(evt.dport)}",
            "bytes": evt.bytes
        }
        state["net_events"].append(payload)
        if evt.event_type in (1, 2):
            state["net_conns"] += 1
    except Exception as e:
        print(f"[cb_net error] {e}", flush=True)

def cb_alert(cpu, data, size):
    try:
        evt = ctypes.cast(data, ctypes.POINTER(Alert)).contents
        payload = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "pid": evt.pid,
            "comm": evt.comm.decode(errors="replace").strip("\x00"),
            "anomaly": ANOM_NAMES.get(evt.anom_type, "UNKNOWN"),
            "detail": evt.extra.decode(errors="replace").strip("\x00") if evt.anom_type != 5 else f"dst={ip4(evt.detail_u32)}",
            "severity": "high" if evt.anom_type in (1, 4, 6) else "med"
        }
        state["alerts"].append(payload)
        state["alert_count"] += 1
    except Exception as e:
        print(f"[cb_alert error] {e}", flush=True)


def bpf_worker():
    try:
        print("=" * 50, flush=True)
        print("BPF Worker Thread Starting...", flush=True)
        print(f"SRC_DIR: {SRC_DIR}", flush=True)
        print(f"SRC_DIR exists: {SRC_DIR.exists()}", flush=True)
        if SRC_DIR.exists():
            print(f"SRC_DIR contents: {list(SRC_DIR.iterdir())}", flush=True)
        print("=" * 50, flush=True)

        state["worker_status"] = "loading"

        b_sc = load_bpf("syscall", "syscall_tracer.c")
        
        b_net = None
        try:
            b_net = load_bpf("network", "network_monitor.c", lambda b: (
                b.attach_kprobe(event="tcp_v4_connect",    fn_name="trace_connect_entry"),
                b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return"),
                b.attach_kretprobe(event="inet_csk_accept",fn_name="trace_accept_return"),
                b.attach_kprobe(event="tcp_sendmsg",       fn_name="trace_tcp_sendmsg"),
                b.attach_kprobe(event="tcp_recvmsg",       fn_name="trace_tcp_recvmsg"),
                b.attach_kretprobe(event="tcp_recvmsg",    fn_name="trace_tcp_recvmsg_return"),
            ))
        except Exception as e:
            print(f"[err] Network monitor attach failed: {e}", flush=True)
            traceback.print_exc()

        b_ad = None
        try:
            b_ad = load_bpf("anomaly", "anomaly_detector.c", lambda b: (
                b.attach_kprobe(event="tcp_v4_connect",    fn_name="trace_connect_entry"),
                b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return"),
            ))
        except Exception as e:
            print(f"[err] Anomaly detector attach failed: {e}", flush=True)
            traceback.print_exc()

        b_cpu = load_bpf("cpu", "cpu_profiler.c")

        ebpf_active = False
        if b_sc is not None:
            try:
                b_sc["events"].open_perf_buffer(cb_syscall, page_cnt=64)
                print("[OK] Syscall perf buffer opened", flush=True)
                ebpf_active = True
            except Exception as e:
                print(f"[err] Syscall perf buffer failed: {e}", flush=True)

        if b_net is not None:
            try:
                b_net["net_events"].open_perf_buffer(cb_net, page_cnt=128)
                print("[OK] Network perf buffer opened", flush=True)
                ebpf_active = True
            except Exception as e:
                print(f"[err] Network perf buffer failed: {e}", flush=True)

        if b_ad is not None:
            try:
                b_ad["alerts"].open_perf_buffer(cb_alert, page_cnt=32)
                print("[OK] Anomaly perf buffer opened", flush=True)
                ebpf_active = True
            except Exception as e:
                print(f"[err] Anomaly perf buffer failed: {e}", flush=True)

        if not ebpf_active:
            state["worker_status"] = "failed"
            state["worker_error"] = "No eBPF programs loaded successfully"
            print("[ERROR] No eBPF programs loaded - no monitoring available", flush=True)
            return

        state["worker_status"] = "running"
        print("=" * 50, flush=True)
        print("eBPF Sentinel Kernel Interface Active!", flush=True)
        print(f"Loaded modules: {state['loaded_modules']}", flush=True)
        print("=" * 50, flush=True)

        # Poll perf buffers and BPF maps indefinitely
        poll_count = 0
        while True:
            for name, b in list(bpfs.items()):
                try:
                    b.perf_buffer_poll(timeout=100)
                except Exception as e:
                    print(f"Poll error {name}: {e}", flush=True)

            # Update CPU histogram and top TX
            try:
                if "cpu" in bpfs:
                    hist = bpfs["cpu"]["runq_lat"]
                    buckets = [0] * 64
                    for k, v in hist.items():
                        if k.value < 64:
                            buckets[k.value] = v.value
                    state["cpu_hist"] = buckets

                if "network" in bpfs:
                    tx_map = bpfs["network"]["tx_bytes"]
                    top_tx = []
                    for k, v in tx_map.items():
                        top_tx.append({"pid": k.value, "bytes": v.value})
                    top_tx.sort(key=lambda x: x["bytes"], reverse=True)
                    state["top_net_tx"] = top_tx[:5]
            except Exception as e:
                print(f"Map poll error: {e}", flush=True)

            # Periodic status log
            poll_count += 1
            if poll_count % 100 == 0:  # Every ~10 seconds
                total_sc = sum(state["sc_counts"].values())
                print(f"[heartbeat] polls={poll_count} syscalls={total_sc} "
                      f"net={len(state['net_events'])} alerts={state['alert_count']}", flush=True)

            time.sleep(0.1)

    except Exception as e:
        state["worker_status"] = "crashed"
        state["worker_error"] = str(e)
        print(f"[FATAL] BPF worker crashed: {e}", flush=True)
        traceback.print_exc()


# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/metrics')
def metrics():
    return jsonify({
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "syscall_events": list(state["sc_events"]),
        "net_events": list(state["net_events"]),
        "alerts": list(state["alerts"]),
        "sc_counts": dict(state["sc_counts"]),
        "net_conns": state["net_conns"],
        "alert_count": state["alert_count"],
        "cpu_hist": state["cpu_hist"],
        "top_net_tx": state["top_net_tx"],
        "worker_status": state["worker_status"],
        "worker_error": state["worker_error"],
        "loaded_modules": state["loaded_modules"],
    })

@app.route('/api/debug')
def debug():
    """Debug endpoint to check BPF worker health"""
    return jsonify({
        "worker_status": state["worker_status"],
        "worker_error": state["worker_error"],
        "loaded_modules": state["loaded_modules"],
        "bpf_instances": list(bpfs.keys()),
        "total_syscall_events": len(state["sc_events"]),
        "total_net_events": len(state["net_events"]),
        "total_alerts": state["alert_count"],
        "sc_counts": dict(state["sc_counts"]),
        "src_dir": str(SRC_DIR),
        "src_dir_exists": SRC_DIR.exists(),
        "src_files": [f.name for f in SRC_DIR.iterdir()] if SRC_DIR.exists() else [],
    })

if __name__ == '__main__':
    import threading
    if os.geteuid() != 0:
        sys.exit("Error: Must run as root to load eBPF programs.")
    
    # Start BPF worker thread
    print("Starting BPF worker thread...", flush=True)
    t = threading.Thread(target=bpf_worker, daemon=True)
    t.start()
    
    # Give BPF worker a moment to start loading
    time.sleep(1)
    
    print(f"Starting Web Dashboard at http://localhost:5000", flush=True)
    app.run(host='0.0.0.0', port=5000, threaded=True)
