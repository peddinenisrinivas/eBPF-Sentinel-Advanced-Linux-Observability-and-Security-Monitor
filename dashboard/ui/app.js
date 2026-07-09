// ============================================
// eBPF Sentinel — HTTP Polling Frontend
// Polls /api/metrics every second for live data
// ============================================

// --- Configuration ---
const POLL_INTERVAL_MS = 1000;
const MAX_LOG_ENTRIES  = 60;
const MAX_ALERT_ENTRIES = 20;
const STALE_TIMEOUT_MS = 5000; // mark offline if no data in 5s

// --- State ---
let syscallCount = 0;
let netCount = 0;
let alertCount = 0;
let lastPollTime = 0;
let pollTimer = null;
let consecutiveErrors = 0;
let isConnected = false;

const syscallData = { openat: 0, execve: 0, read: 0, write: 0 };

// Track what we've already rendered to avoid duplicates
let seenSyscallKeys = new Set();
let seenNetKeys     = new Set();
let seenAlertKeys   = new Set();

// Generate a unique key for deduplication
function eventKey(evt, prefix) {
    return `${prefix}_${evt.timestamp}_${evt.pid}_${evt.comm}_${(evt.syscall || evt.type || evt.anomaly || '')}`;
}

// --- Charts ---
const ctx = document.getElementById('syscallChart').getContext('2d');
const scChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['openat', 'execve', 'read', 'write'],
        datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: [
                'rgba(99, 102, 241, 0.85)',
                'rgba(16, 185, 129, 0.85)',
                'rgba(245, 158, 11, 0.85)',
                'rgba(239, 68, 68, 0.85)'
            ],
            borderColor: [
                'rgba(99, 102, 241, 1)',
                'rgba(16, 185, 129, 1)',
                'rgba(245, 158, 11, 1)',
                'rgba(239, 68, 68, 1)'
            ],
            borderWidth: 2,
            hoverOffset: 8,
            hoverBorderWidth: 3,
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 600, easing: 'easeOutQuart' },
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    color: '#94a3b8',
                    font: { family: 'Outfit', size: 12 },
                    padding: 16,
                    usePointStyle: true,
                    pointStyleWidth: 10,
                }
            },
            tooltip: {
                backgroundColor: 'rgba(13, 15, 20, 0.9)',
                titleFont: { family: 'Outfit', weight: '600' },
                bodyFont: { family: 'JetBrains Mono', size: 12 },
                padding: 12,
                cornerRadius: 8,
                borderColor: 'rgba(99, 102, 241, 0.3)',
                borderWidth: 1,
            }
        },
        cutout: '72%'
    }
});

const cpuLatCtx = document.getElementById('cpuLatChart').getContext('2d');
const cpuChart = new Chart(cpuLatCtx, {
    type: 'bar',
    data: {
        labels: Array.from({length: 64}, (_, i) => {
            const ns = Math.pow(2, i);
            if (ns < 1000) return `${ns}ns`;
            if (ns < 1e6) return `${(ns/1000).toFixed(0)}µs`;
            if (ns < 1e9) return `${(ns/1e6).toFixed(0)}ms`;
            return `${(ns/1e9).toFixed(0)}s`;
        }),
        datasets: [{
            label: 'Wait Count',
            data: new Array(64).fill(0),
            backgroundColor: 'rgba(99, 102, 241, 0.6)',
            hoverBackgroundColor: 'rgba(99, 102, 241, 0.9)',
            borderRadius: 2,
            borderSkipped: false,
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        scales: {
            x: {
                display: false,
                grid: { display: false }
            },
            y: {
                display: true,
                grid: { color: 'rgba(255,255,255,0.04)' },
                ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
            }
        },
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: 'rgba(13, 15, 20, 0.9)',
                titleFont: { family: 'Outfit' },
                bodyFont: { family: 'JetBrains Mono', size: 11 },
                cornerRadius: 8,
            }
        }
    }
});

// --- DOM References ---
const logContainer    = document.getElementById('activity-log');
const alertsContainer = document.getElementById('alerts-list');
const statusEl        = document.querySelector('.status');
const statSyscalls    = document.getElementById('stat-syscalls');
const statNet         = document.getElementById('stat-net');
const statAlerts      = document.getElementById('stat-alerts');
const lastUpdateEl    = document.getElementById('last-update');

// --- UI Helpers ---
function addLogEntry(data, category) {
    const div = document.createElement('div');
    div.className = `log-entry ${category}-row`;
    div.dataset.category = category;

    const time = `<span class="time">${data.timestamp}</span>`;
    const type = `<span class="type ${category}">${data.type || data.syscall}</span>`;
    const comm = `<span class="comm">${data.comm} <span class="pid-badge">[${data.pid}]</span></span>`;

    let detailText = data.fname || data.dst || '';
    if (!detailText && (data.syscall === 'read' || data.syscall === 'write')) {
        detailText = `${data.ret} bytes`;
    }
    const detail = `<span class="detail">${detailText}</span>`;

    div.innerHTML = `${time}${type}${comm}${detail}`;
    logContainer.prepend(div);

    // Trim old entries
    while (logContainer.children.length > MAX_LOG_ENTRIES) {
        logContainer.removeChild(logContainer.lastChild);
    }

    // Respect active filter
    const activeFilter = document.querySelector('.filter-btn.active')?.dataset?.filter || 'all';
    if (activeFilter !== 'all' && activeFilter !== category) {
        div.style.display = 'none';
    }
}

function addAlertEntry(data) {
    if (alertsContainer.querySelector('.empty-state')) {
        alertsContainer.innerHTML = '';
    }

    const div = document.createElement('div');
    div.className = `alert-entry ${data.severity}`;
    
    div.innerHTML = `
        <div class="alert-header">
            <span class="alert-title">${data.anomaly} DETECTED</span>
            <span class="alert-time">${data.timestamp}</span>
        </div>
        <div class="alert-desc">
            Process <strong>${data.comm}</strong> (PID ${data.pid}): ${data.detail}
        </div>
    `;

    alertsContainer.prepend(div);
    while (alertsContainer.children.length > MAX_ALERT_ENTRIES) {
        alertsContainer.removeChild(alertsContainer.lastChild);
    }
}

function updateTopNet(data) {
    const list = document.getElementById('top-net-list');
    if (!data || data.length === 0) {
        list.innerHTML = '<div class="empty-state">Calculating...</div>';
        return;
    }
    list.innerHTML = data.map(item => `
        <div class="log-entry mini">
            <span class="mini-pid">PID ${item.pid}</span>
            <span class="mini-bytes">${(item.bytes / 1024).toFixed(1)} KB</span>
        </div>
    `).join('');
}

// --- Connection Status ---
function setConnected(workerStatus, loadedModules) {
    consecutiveErrors = 0;
    
    if (workerStatus === 'crashed' || workerStatus === 'failed') {
        statusEl.innerHTML = `<span class="pulse offline"></span> BPF Worker ${workerStatus}`;
        statusEl.className = 'status disconnected';
        isConnected = false;
        return;
    }
    
    if (workerStatus === 'loading' || workerStatus === 'starting') {
        statusEl.innerHTML = '<span class="pulse reconnecting"></span> Loading eBPF programs...';
        statusEl.className = 'status reconnecting';
        isConnected = false;
        return;
    }

    if (!isConnected) {
        isConnected = true;
        const modCount = loadedModules ? loadedModules.length : 0;
        statusEl.innerHTML = `<span class="pulse"></span> Live — ${modCount} BPF modules`;
        statusEl.className = 'status connected';
    }
    pulseIndicator();
}

function setDisconnected(reason) {
    isConnected = false;
    const msg = reason || 'Connection lost';
    statusEl.innerHTML = `<span class="pulse offline"></span> ${msg}`;
    statusEl.className = 'status disconnected';
}

function setReconnecting() {
    statusEl.innerHTML = '<span class="pulse reconnecting"></span> Reconnecting...';
    statusEl.className = 'status reconnecting';
}

function pulseIndicator() {
    statusEl.classList.add('active-pulse');
    setTimeout(() => statusEl.classList.remove('active-pulse'), 200);
}

// --- Core Polling Loop ---
async function fetchMetrics() {
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);

        const response = await fetch('/api/metrics', { signal: controller.signal });
        clearTimeout(timeout);

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        setConnected(data.worker_status, data.loaded_modules);
        lastPollTime = Date.now();

        // Update last-updated timestamp
        if (lastUpdateEl) {
            lastUpdateEl.textContent = data.timestamp || new Date().toLocaleTimeString();
        }

        // --- Process Syscall Events ---
        if (data.syscall_events) {
            data.syscall_events.forEach(evt => {
                const key = eventKey(evt, 'sc');
                if (!seenSyscallKeys.has(key)) {
                    seenSyscallKeys.add(key);
                    syscallCount++;
                    if (syscallData[evt.syscall] !== undefined) {
                        syscallData[evt.syscall]++;
                    }
                    addLogEntry(evt, 'syscall');
                }
            });
            // Keep set bounded
            if (seenSyscallKeys.size > 200) {
                const arr = [...seenSyscallKeys];
                seenSyscallKeys = new Set(arr.slice(-100));
            }
        }
        statSyscalls.textContent = syscallCount.toLocaleString();

        // --- Process Network Events ---
        if (data.net_events) {
            data.net_events.forEach(evt => {
                const key = eventKey(evt, 'net');
                if (!seenNetKeys.has(key)) {
                    seenNetKeys.add(key);
                    netCount++;
                    addLogEntry(evt, 'net');
                }
            });
            if (seenNetKeys.size > 200) {
                const arr = [...seenNetKeys];
                seenNetKeys = new Set(arr.slice(-100));
            }
        }
        statNet.textContent = netCount.toLocaleString();

        // --- Process Alerts ---
        if (data.alerts) {
            data.alerts.forEach(alert => {
                const key = eventKey(alert, 'alert');
                if (!seenAlertKeys.has(key)) {
                    seenAlertKeys.add(key);
                    alertCount++;
                    addAlertEntry(alert);
                }
            });
            if (seenAlertKeys.size > 100) {
                const arr = [...seenAlertKeys];
                seenAlertKeys = new Set(arr.slice(-50));
            }
        }
        statAlerts.textContent = alertCount.toLocaleString();

        // --- CPU Histogram ---
        if (data.cpu_hist && data.cpu_hist.some(v => v > 0)) {
            cpuChart.data.datasets[0].data = data.cpu_hist;
            cpuChart.update('none'); // skip animation for perf
        }

        // --- Top Bandwidth ---
        updateTopNet(data.top_net_tx);

        // --- Update Syscall Chart (debounced) ---
        scheduleChartUpdate();

    } catch (err) {
        consecutiveErrors++;
        console.warn(`Poll error (#${consecutiveErrors}):`, err.message);

        if (consecutiveErrors >= 3) {
            setDisconnected('Server unreachable');
        } else {
            setReconnecting();
        }
    }
}

// --- Chart Update (Debounced) ---
let chartTimeout;
function scheduleChartUpdate() {
    clearTimeout(chartTimeout);
    chartTimeout = setTimeout(() => {
        scChart.data.datasets[0].data = [
            syscallData.openat,
            syscallData.execve,
            syscallData.read,
            syscallData.write
        ];
        scChart.update();
    }, 500);
}

// --- Filters ---
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        const filter = btn.dataset.filter;
        const entries = logContainer.querySelectorAll('.log-entry');
        
        entries.forEach(entry => {
            if (filter === 'all' || entry.dataset.category === filter) {
                entry.style.display = 'grid';
            } else {
                entry.style.display = 'none';
            }
        });
    });
});

// --- Start Polling ---
console.log('🛡️ eBPF Sentinel — starting HTTP polling...');
fetchMetrics(); // Initial fetch
pollTimer = setInterval(fetchMetrics, POLL_INTERVAL_MS);

// --- Visibility-aware polling (pause when tab hidden) ---
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        clearInterval(pollTimer);
        pollTimer = null;
    } else {
        // Immediately fetch then resume interval
        fetchMetrics();
        pollTimer = setInterval(fetchMetrics, POLL_INTERVAL_MS);
    }
});
