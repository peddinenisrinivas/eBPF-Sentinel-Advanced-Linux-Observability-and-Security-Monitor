#!/usr/bin/env bash
# scripts/setup.sh
# Install all dependencies for the eBPF Performance Tool
# Tested on Ubuntu 20.04, 22.04, 24.04 and Debian 11/12

set -euo pipefail

RED='\033[91m'; GRN='\033[92m'; YEL='\033[93m'; BOLD='\033[1m'; RST='\033[0m'
info()  { echo -e "${BOLD}[INFO]${RST}  $*"; }
ok()    { echo -e "${GRN}[OK]${RST}    $*"; }
warn()  { echo -e "${YEL}[WARN]${RST}  $*"; }
err()   { echo -e "${RED}[ERR]${RST}   $*"; exit 1; }

# ── Root check ──
[[ $EUID -ne 0 ]] && err "Run as root: sudo bash scripts/setup.sh"

# ── Kernel version check ──
KVER=$(uname -r)
KMAJ=$(uname -r | cut -d. -f1)
KMIN=$(uname -r | cut -d. -f2)
info "Kernel: $KVER"
if [[ $KMAJ -lt 4 ]] || ( [[ $KMAJ -eq 4 ]] && [[ $KMIN -lt 9 ]] ); then
    err "Kernel >= 4.9 required for eBPF. Upgrade your kernel."
fi
ok "Kernel version OK"

# ── eBPF config check ──
KCFG="/boot/config-$(uname -r)"
if [[ -f $KCFG ]]; then
    for flag in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT; do
        if ! grep -q "^${flag}=y" "$KCFG" 2>/dev/null; then
            warn "$flag not set in kernel config — eBPF may not work"
        else
            ok "$flag enabled"
        fi
    done
fi

# ── Detect distro ──
if   [[ -f /etc/debian_version ]]; then DISTRO="debian"
elif [[ -f /etc/fedora-release ]]; then DISTRO="fedora"
elif [[ -f /etc/arch-release   ]]; then DISTRO="arch"
else warn "Unknown distro, attempting Debian-style install"; DISTRO="debian"; fi

info "Distro: $DISTRO"

# ── Install packages ──
case $DISTRO in
  debian)
    apt-get update -qq
    apt-get install -y \
      bpfcc-tools \
      python3-bpfcc \
      linux-headers-$(uname -r) \
      clang \
      llvm \
      libelf-dev \
      python3-pip \
      python3-rich \
      stress-ng \
      curl \
      2>/dev/null || warn "Some packages may have failed"
    ;;
  fedora)
    dnf install -y \
      bcc bcc-tools python3-bcc \
      kernel-devel-$(uname -r) \
      clang llvm elfutils-libelf-devel \
      python3-pip stress-ng
    ;;
  arch)
    pacman -Sy --noconfirm bcc python-bcc linux-headers clang llvm stress-ng
    ;;
esac

ok "Packages installed"

# ── Python deps ──
pip3 install --quiet rich psutil 2>/dev/null || warn "pip install failed"
ok "Python dependencies installed"

# ── Verify bcc ──
if python3 -c "from bcc import BPF; print('BCC OK')" 2>/dev/null; then
    ok "BCC Python bindings working"
else
    warn "BCC Python import failed — may need reboot or manual BCC build"
fi

# ── Permissions ──
# Allow non-root to load eBPF programs (optional, for dev convenience)
# sysctl -w kernel.unprivileged_bpf_disabled=0 2>/dev/null || true

echo ""
echo -e "${BOLD}${GRN}Setup complete!${RST}"
echo ""
echo "  Run tools (as root):"
echo "    sudo python3 tools/syscall_tracer.py"
echo "    sudo python3 tools/cpu_profiler.py --duration 30"
echo "    sudo python3 tools/network_monitor.py"
echo "    sudo python3 tools/anomaly_detector.py"
echo "    sudo python3 dashboard/dashboard.py"
echo ""
