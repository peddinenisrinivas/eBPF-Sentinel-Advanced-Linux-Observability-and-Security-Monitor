#!/bin/bash
# scripts/generate_load.sh
# Generates artificial load to test the eBPF Sentinel Dashboard

echo "🚀 Starting Artificial Load Generation..."

# 1. Syscall Load (Files & Processes)
echo "📂 Generating Syscall traffic..."
for i in {1..20}; do
    ls -R /etc > /dev/null 2>&1
    sleep 0.1
    cat /etc/passwd > /dev/null
    echo "Activity log entry $i" >> /tmp/sentinel_test.log
done

# 2. Network Load (Connections)
echo "🌐 Generating Network traffic..."
for i in {1..10}; do
    curl -s https://www.google.com > /dev/null
    curl -s https://www.github.com > /dev/null
    sleep 0.2
done

# 3. Security Anomalies
echo "🛡️  Triggering Alerts..."

# Privilege Escalation (simulated)
sudo python3 -c "import os; os.setuid(0); print('Triggered: PRIVESC')"

# File Storm
echo "🔥 Triggering File Storm..."
for i in {1..150}; do
    touch "/tmp/storm_$i"
done
rm /tmp/storm_*

# mprotect (PROT_EXEC)
echo "🧠 Triggering mprotect(EXEC)..."
python3 -c "import ctypes, mmap; m = mmap.mmap(-1, 4096); libc = ctypes.CDLL('libc.so.6'); libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]; buf_addr = ctypes.addressof(ctypes.c_char.from_buffer(m)); libc.mprotect(buf_addr, 4096, 0x4)"


