/* 
 * Silence macro redefinition warnings by undefining them before includes.
 */
#undef __HAVE_BUILTIN_BSWAP16__
#undef __HAVE_BUILTIN_BSWAP32__
#undef __HAVE_BUILTIN_BSWAP64__



/*
 * syscall_tracer.c
 * eBPF program to trace key system calls: open, execve, read, write
 * Loaded by tools/syscall_tracer.py via BCC
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

/* ---- Event structure sent to userspace via perf ring buffer ---- */
struct event_t {
    u32  pid;
    u32  uid;
    char comm[TASK_COMM_LEN];   /* process name (16 bytes) */
    char fname[256];             /* file/arg involved       */
    int  ret;                    /* return value            */
    u64  ts_ns;                  /* timestamp nanoseconds   */
    u8   syscall_id;             /* 0=open 1=execve 2=read 3=write */
};



/* Perf output map — kernel pushes events, Python reads them */
BPF_PERF_OUTPUT(events);

/* Scratch map: store args at entry, read at return */
BPF_HASH(infotbl, u64, struct event_t);

/* ----------------------------------------------------------------
 * Helper: fill common fields
 * ----------------------------------------------------------------*/
static inline void fill_common(struct event_t *e, u8 syscall_id) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid        = pid_tgid >> 32;
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ts_ns      = bpf_ktime_get_ns();
    e->syscall_id = syscall_id;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ================================================================
 * OPEN syscall — trace which files are being opened
 * ================================================================*/
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t e = {};
    fill_common(&e, 0);
    bpf_probe_read_user_str(e.fname, sizeof(e.fname), args->filename);

    u64 id = bpf_get_current_pid_tgid();
    infotbl.update(&id, &e);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u64 id = bpf_get_current_pid_tgid();
    struct event_t *ep = infotbl.lookup(&id);
    if (!ep) return 0;

    ep->ret = args->ret;
    events.perf_submit(args, ep, sizeof(*ep));
    infotbl.delete(&id);
    return 0;
}

/* ================================================================
 * EXECVE — trace process execution (command launches)
 * ================================================================*/
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t e = {};
    fill_common(&e, 1);
    bpf_probe_read_user_str(e.fname, sizeof(e.fname), args->filename);

    u64 id = bpf_get_current_pid_tgid();
    infotbl.update(&id, &e);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    u64 id = bpf_get_current_pid_tgid();
    struct event_t *ep = infotbl.lookup(&id);
    if (!ep) return 0;

    ep->ret = args->ret;
    events.perf_submit(args, ep, sizeof(*ep));
    infotbl.delete(&id);
    return 0;
}

/* ================================================================
 * READ / WRITE — track bytes transferred per process
 * ================================================================*/
BPF_HASH(read_bytes,  u32, u64);   /* pid -> cumulative bytes read  */
BPF_HASH(write_bytes, u32, u64);   /* pid -> cumulative bytes written */

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    if (args->ret <= 0) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 zero = 0;
    u64 *val = read_bytes.lookup_or_try_init(&pid, &zero);
    if (val) lock_xadd(val, args->ret);

    /* NEW: Submit event for the dashboard */
    struct event_t e = {};
    fill_common(&e, 2);
    e.ret = args->ret;
    events.perf_submit(args, &e, sizeof(e));

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    if (args->ret <= 0) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 zero = 0;
    u64 *val = write_bytes.lookup_or_try_init(&pid, &zero);
    if (val) lock_xadd(val, args->ret);

    /* NEW: Submit event for the dashboard */
    struct event_t e = {};
    fill_common(&e, 3);
    e.ret = args->ret;
    events.perf_submit(args, &e, sizeof(e));

    return 0;
}
