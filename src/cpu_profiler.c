/* 
 * Silence macro redefinition warnings by undefining them before includes.
 * These are often injected by BCC/Clang and conflict with kernel headers.
 */
#undef __HAVE_BUILTIN_BSWAP16__
#undef __HAVE_BUILTIN_BSWAP32__
#undef __HAVE_BUILTIN_BSWAP64__



/*
 * cpu_profiler.c
 * eBPF program for CPU profiling:
 *   - Per-process CPU on/off-CPU time
 *   - Function latency histograms via uprobes (when used with funclatency)
 *   - Scheduler run-queue latency (time spent waiting for CPU)
 * Loaded by tools/cpu_profiler.py via BCC
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

/* ---- Data structures ---- */

struct pid_key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct latency_key_t {
    u32  pid;
    u64  slot;   /* log2 histogram slot */
};

/* ---- Maps ---- */

/* Track when each task was enqueued (about to run) */
BPF_HASH(enqueue_ts, u32, u64);

/* Run-queue latency histogram: pid -> log2(ns) -> count */
BPF_HISTOGRAM(runq_lat, u64, 64);

/* On-CPU time accumulator: pid -> total ns on CPU */
BPF_HASH(oncpu_ns, u32, u64);

/* Off-CPU time accumulator: pid -> total ns off CPU */
BPF_HASH(offcpu_ns, u32, u64);

/* CPU sample counts (for flame graph profiling) */
BPF_HASH(counts, struct pid_key_t, u64);

/* Per-pid start time when they went off-CPU */
BPF_HASH(start_offcpu, u32, u64);

/* ================================================================
 * Scheduler: record when a task wakes up (enters run queue)
 * ================================================================*/
RAW_TRACEPOINT_PROBE(sched_wakeup) {
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    u32 pid = p->pid;
    u64 ts  = bpf_ktime_get_ns();
    enqueue_ts.update(&pid, &ts);
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new) {
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    u32 pid = p->pid;
    u64 ts  = bpf_ktime_get_ns();
    enqueue_ts.update(&pid, &ts);
    return 0;
}

/* ================================================================
 * Scheduler switch: measure run-queue latency and off-CPU time
 * ================================================================*/
RAW_TRACEPOINT_PROBE(sched_switch) {
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u64 ts = bpf_ktime_get_ns();

    /* --- Outgoing task (going off-CPU) --- */
    u32 prev_pid = prev->pid;
    if (prev_pid != 0) {
        /* Record when it went off-CPU */
        start_offcpu.update(&prev_pid, &ts);

        /* Compute how long it was running (on-CPU delta) */
        u64 *ots = enqueue_ts.lookup(&prev_pid);
        if (ots) {
            u64 delta = ts - *ots;
            u64 zero  = 0;
            u64 *acc  = oncpu_ns.lookup_or_try_init(&prev_pid, &zero);
            if (acc) lock_xadd(acc, delta);
        }
    }

    /* --- Incoming task (going on-CPU) --- */
    u32 next_pid = next->pid;
    if (next_pid != 0) {
        /* Run-queue latency = now - enqueue time */
        u64 *eq = enqueue_ts.lookup(&next_pid);
        if (eq) {
            u64 rqlat = ts - *eq;
            runq_lat.increment(bpf_log2l(rqlat));
            enqueue_ts.delete(&next_pid);
        }

        /* Off-CPU time for incoming task */
        u64 *offts = start_offcpu.lookup(&next_pid);
        if (offts) {
            u64 delta = ts - *offts;
            u64 zero  = 0;
            u64 *acc  = offcpu_ns.lookup_or_try_init(&next_pid, &zero);
            if (acc) lock_xadd(acc, delta);
            start_offcpu.delete(&next_pid);
        }
    }

    return 0;
}

/* ================================================================
 * CPU sampling — called by perf_event (99 Hz) for flame graphs
 * ================================================================*/
int do_perf_event(struct bpf_perf_event_data *ctx) {
    struct pid_key_t key = {};
    key.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    u64 zero = 0;
    u64 *val = counts.lookup_or_try_init(&key, &zero);
    if (val) (*val)++;
    return 0;
}
