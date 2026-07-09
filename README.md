# 🛡️ eBPF Sentinel: Advanced Linux Observability

**eBPF Sentinel** is a high-performance Linux kernel observability and security tool. By leveraging the power of **eBPF (Extended Berkeley Packet Filter)**, it monitors system activity directly from within the kernel with minimal overhead and zero modification to source code.

It provides a unified view of system health, network traffic, and security anomalies, making it ideal for SREs, Security Researchers, and System Administrators.

---

## Project Structure

```
ebpf_tool/
├── app.py # Main entry point — Flask web server + BPF loader
├── requirements.txt # Python dependencies
├── simulate_load.sh # Quick load-simulation helper
├── src/ # eBPF C source files (compiled at runtime by BCC)
├── tools/
│ ├── syscall_tracer.py # Standalone syscall tracing CLI
│ ├── cpu_profiler.py # CPU profiling CLI
│ ├── network_monitor.py # Network connection monitoring CLI
│ └── anomaly_detector.py # Security anomaly detection CLI
├── dashboard/
│ └── dashboard.py # Terminal dashboard (rich-based)
└── scripts/
 ├── setup.sh # Automated dependency installer
 ├── generate_load.sh # Load generator for testing
 └── run_demo.sh # Full demo runner

```
---

## 🚀 Key Features

### 🔍 System Visibility
- **Deep Syscall Tracing**: Real-time monitoring of sensitive system calls (`open`, `exec`, `read`, `write`).
- **CPU Profiling**: High-frequency sampling of process execution and scheduler latency.
- **Micro-Observability**: Detect patterns that traditional tools like `top` or `ps` miss.

### 🌐 Network Intelligence
- **Connection Tracking**: Full visibility into TCP `connect()` and `accept()` events.
- **Traffic Analysis**: Per-process throughput monitoring (bytes sent/received).
- **IP Reputation**: Automatically flags connections to never-before-seen destination IPs.

### 🛡️ Security Anomaly Detection
- **Privilege Escalation**: Detects unauthorized `setuid(0)` calls in real-time.
- **Malware Patterns**: Identifies "fileless" execution via `memfd_create` and `ptrace` injections.
- **Stability Protection**: Built-in detection for Fork Bombs and File Open Storms.

---

## 🛠️ Architecture

The tool follows a **dual-layer architecture**:
1.  **Kernel Layer (C / eBPF)**: Safe, high-performance programs compiled to BPF bytecode and verified by the kernel. They capture raw events and update atomic maps.
2.  **User Layer (Python / BCC)**: Loads BPF programs, aggregates map data, and provides a modern UI for human consumption.

---

## 📦 Installation & Setup

### Prerequisites
- Linux Kernel ≥ 4.9 (5.x+ recommended)
- BCC (BPF Compiler Collection)
- Python 3.8+

### Quick Install
```bash
sudo bash scripts/setup.sh
```

---

## 🖥️ Usage

### Modern Dashboard (Recommended)
Launch the real-time web interface:
```bash
sudo python3 app.py
```
*Accessible at http://localhost:5000*

### CLI Tools
Run individual monitors for specific debugging:
```bash
sudo python3 tools/syscall_tracer.py
sudo python3 tools/network_monitor.py
sudo python3 tools/anomaly_detector.py
```

---

## 📈 Anomaly Ruleset

| Anomaly | Severity | Trigger |
| :--- | :--- | :--- |
| **Privilege Escalation** | 🔴 Critical | Process acquired UID 0 via `setuid`. |
| **Fork Bomb** | 🔴 Critical | Process spawning > 50 children/sec. |
| **New Destination** | 🟡 Warning | Connection to an IP never seen by this host. |
| **File Storm** | 🟡 Warning | > 100 `open()` calls/sec (possible scanning). |
| **Rare Syscall** | ⚪ Info | Use of `ptrace` or `memfd_create`. |

---

## 🎮 How to Run the Demo

To see eBPF Sentinel in action and verify the dashboard is working, try these demo scenarios:

### 1. Generate Syscall Traffic
Run a series of commands to populate the **Syscall Distribution** chart:
```bash
# Triggers many openat/read/write calls
find /etc -type f -exec cat {} + > /dev/null 2>&1
```

### 2. Monitor Network Activity
Watch the **Live Logs** and **Top Bandwidth** update in real-time:
```bash
# Generates outbound connect events
curl -s https://www.google.com > /dev/null
# Generates high-throughput TX traffic
dd if=/dev/zero bs=1M count=100 | nc 127.0.0.1 1234  # (If nc listener exists)
# if the nc listenr is not there the run this first
nc -l 1234    # start this first
```

### 3. Trigger Security Anomalies
Test the detection engine with these "suspicious" activities:

*   **Privilege Escalation**: Run a simple Python snippet to acquire root (must be run as root to work, will be flagged regardless).
    ```bash
    sudo python3 -c "import os; os.setuid(0); print('I am root')"
    ```
*   **File Open Storm**: Rapidly open files to trigger the rate limiter.
    ```bash
    for i in {1..150}; do touch /tmp/test_file_$i; done
    ```
*   **Fork Bomb Detection**: Warning: Only run this if you know how to recover, or use a restricted limit!
    ```bash
    # A safe-ish version that spawns many processes quickly
    for i in {1..60}; do (sleep 1 &); done
    ```
*   **Memory Protection Warning**: Detect processes making memory executable (typical of shellcode).
    ```bash
    # Uses ctypes to call libc.mprotect on a memory-mapped region
    python3 -c "import ctypes, mmap; m = mmap.mmap(-1, 4096); libc = ctypes.CDLL('libc.so.6'); libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]; buf_addr = ctypes.addressof(ctypes.c_char.from_buffer(m)); libc.mprotect(buf_addr, 4096, 0x4); print('mprotect called')"
    ```

### 4. Generate Load(Other option)
Instead of running the above commands manually, you can generate load using:
```bash
sudo ./scripts/generate_load.sh
```
---

## 🛠️ Troubleshooting
- **Warnings?** BCC compilation warnings are often due to kernel header mismatches or minor macro issues, and most are harmless unless they prevent the eBPF program from loading. 
- **No Data?** Ensure you are running with `sudo` and that your kernel has `CONFIG_BPF_SYSCALL=y`.
- **CONFIG_BPF_SYSCALL not set?** eBPF requires this flag compiled into the kernel. It is enabled by default on stock Ubuntu and Debian kernels. On custom or embedded kernels it may need to be set and the kernel recompiled. 
- **from bcc import BPF' fails after install?** This can occur if kernel headers do not match the running kernel. Run: sudo apt install linux-headers-$(uname -r). A reboot may be required after the initial BCC install. 