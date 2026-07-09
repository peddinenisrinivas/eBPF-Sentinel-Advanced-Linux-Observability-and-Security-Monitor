#!/usr/bin/env bash
# scripts/run_demo.sh
# Step-by-step demo script for presentation.
# Each section pauses and waits for Enter before proceeding.
# Run in a large terminal (≥ 200x50 recommended).

BOLD='\033[1m'; DIM='\033[2m'; GRN='\033[92m'
YEL='\033[93m'; RED='\033[91m'; CYN='\033[96m'; RST='\033[0m'

pause() {
    echo ""
    echo -e "${DIM}  ── Press [Enter] for next step ──${RST}"
    read -r
}

banner() {
    echo ""
    echo -e "${BOLD}${CYN}══════════════════════════════════════════════${RST}"
    echo -e "${BOLD}${CYN}  $1${RST}"
    echo -e "${BOLD}${CYN}══════════════════════════════════════════════${RST}"
    echo ""
}

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash scripts/run_demo.sh"; exit 1; }

clear
banner "eBPF Performance Tool — Live Demo"
echo -e "  ${DIM}No kernel modification required.${RST}"
echo -e "  ${DIM}eBPF programs run safely inside the kernel verifier sandbox.${RST}"
pause

# ── Step 1: Syscall Tracer ──
banner "DEMO 1 — Syscall Tracer (openat + execve)"
echo -e "  ${YEL}What you'll see:${RST}"
echo "  • Real-time open() calls — every file the OS touches"
echo "  • execve() — every process launch"
echo "  • Return code shows success (≥0) or error (<0)"
echo ""
echo -e "  ${DIM}Running for 15 seconds. Open another terminal to generate activity.${RST}"
pause

timeout 15 python3 tools/syscall_tracer.py 2>/dev/null || true

# ── Step 2: CPU Profiler ──
banner "DEMO 2 — CPU Profiler (latency histogram)"
echo -e "  ${YEL}What you'll see:${RST}"
echo "  • Run-queue latency histogram (log2 scale, nanoseconds)"
echo "  • Shows how long processes WAIT for the CPU"
echo "  • Top processes by on-CPU vs off-CPU time"
echo ""
echo -e "  ${DIM}Generating CPU load in background, profiling for 10 seconds ...${RST}"
pause

stress-ng --cpu 1 --timeout 12s --quiet &
STRESS=$!
sleep 1
python3 tools/cpu_profiler.py --duration 10 --interval 10
kill $STRESS 2>/dev/null || true

# ── Step 3: Network Monitor ──
banner "DEMO 3 — Network Monitor"
echo -e "  ${YEL}What you'll see:${RST}"
echo "  • Every TCP connect and accept — with IP and port"
echo "  • Which process initiated each connection"
echo "  • Bytes sent/received per process"
echo ""
echo -e "  ${DIM}Making outbound connections, tracing for 12 seconds ...${RST}"
pause

(
  sleep 1
  for url in http://example.com http://google.com http://github.com; do
    curl -s --max-time 3 "$url" > /dev/null 2>&1 &
  done
) &
timeout 12 python3 tools/network_monitor.py --no-send-recv 2>/dev/null || true

# ── Step 4: Anomaly Detector ──
banner "DEMO 4 — Anomaly Detector"
echo -e "  ${YEL}What you'll see:${RST}"
echo "  • Privilege escalation attempts (setuid to root)"
echo "  • First-seen destination IPs flagged as anomalies"
echo "  • Rare syscalls: ptrace, memfd_create"
echo "  • File open storms and fork bombs"
echo ""
echo -e "  ${RED}Simulating suspicious activity in background ...${RST}"
pause

# Simulate anomalous activity in background
(
  sleep 2
  # File storm
  for i in $(seq 1 150); do cat /proc/version > /dev/null 2>&1; done
  # New IP connections
  curl -s --max-time 2 http://93.184.216.34 > /dev/null 2>&1 || true   # example.com IP
  curl -s --max-time 2 http://140.82.121.4  > /dev/null 2>&1 || true   # github.com IP
) &

timeout 15 python3 tools/anomaly_detector.py 2>/dev/null || true

# ── Step 5: Live Dashboard ──
banner "DEMO 5 — Live Dashboard (all-in-one)"
echo -e "  ${YEL}What you'll see:${RST}"
echo "  • Unified view of all four monitors"
echo "  • Refreshes every 2 seconds"
echo "  • Syscall counts, recent events, network, and alerts"
echo ""
echo -e "  ${DIM}Running for 20 seconds. Generating background activity ...${RST}"
pause

bash scripts/generate_load.sh 20 &
LOAD_PID=$!
sleep 1
timeout 20 python3 dashboard/dashboard.py 2>/dev/null || true
kill $LOAD_PID 2>/dev/null || true

# ── Wrap up ──
banner "Demo Complete"
echo -e "  ${GRN}Key takeaways:${RST}"
echo "  1. eBPF runs in kernel space — zero overhead when idle"
echo "  2. Kernel verifier guarantees safety — no crashes, no kernel mods"
echo "  3. Perf ring buffers: kernel pushes events, Python reads them"
echo "  4. BPF maps enable stateful tracking: histograms, counters, sets"
echo "  5. All four tools use the same eBPF pattern: C program + Python loader"
echo ""
echo -e "  ${DIM}Source: ebpf_tool/  |  Questions?${RST}"
echo ""
