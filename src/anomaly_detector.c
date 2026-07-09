/* 
 * Silence macro redefinition warnings by undefining them before includes.
 */
#undef __HAVE_BUILTIN_BSWAP16__
#undef __HAVE_BUILTIN_BSWAP32__
#undef __HAVE_BUILTIN_BSWAP64__


/*
 * anomaly_detector.c

 * eBPF program to detect suspicious kernel-level behavior:
 *   1. Privilege escalation (setuid/setgid to root)
 *   2. Unexpected outbound connections to new IPs
 *   3. Rare / dangerous syscalls (ptrace, mprotect+exec, memfd)
 *   4. Excessive file open rate (possible exfiltration/scan)
 *   5. Fork bombs (rapid child spawning)
 * Loaded by tools/anomaly_detector.py via BCC
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/inet_sock.h>

/* ---- Anomaly types ---- */
#define ANOM_PRIVESC        1   /* uid 0 acquired                   */
#define ANOM_RARE_SYSCALL   2   /* ptrace / memfd_create / etc.     */
#define ANOM_FILE_STORM     3   /* >100 opens/sec from one process  */
#define ANOM_FORK_BOMB      4   /* >50 forks/sec                    */
#define ANOM_NEW_DEST_IP    5   /* first-seen destination IP        */
#define ANOM_EXEC_MPROTECT  6   /* mprotect(PROT_EXEC) on heap/anon */

/* ---- Alert event sent to userspace ---- */
struct alert_t {
    u32  pid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    u8   anom_type;
    u32  detail_u32;    /* IP addr / syscall nr / count */
    u64  ts_ns;
    char extra[64];     /* human-readable extra info */
};



BPF_PERF_OUTPUT(alerts);

/* ================================================================
 * 1. Privilege Escalation — setuid(0) / setreuid(0,0)
 * ================================================================*/
TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    if (args->uid != 0) return 0;   /* only care about escalation to root */

    struct alert_t a = {};
    a.pid       = bpf_get_current_pid_tgid() >> 32;
    a.uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    a.ts_ns     = bpf_ktime_get_ns();
    a.anom_type = ANOM_PRIVESC;
    bpf_get_current_comm(&a.comm, sizeof(a.comm));
    __builtin_memcpy(a.extra, "setuid(0) called", 17);
    alerts.perf_submit(args, &a, sizeof(a));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setreuid) {
    if (args->ruid != 0 && args->euid != 0) return 0;

    struct alert_t a = {};
    a.pid       = bpf_get_current_pid_tgid() >> 32;
    a.uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    a.ts_ns     = bpf_ktime_get_ns();
    a.anom_type = ANOM_PRIVESC;
    bpf_get_current_comm(&a.comm, sizeof(a.comm));
    __builtin_memcpy(a.extra, "setreuid to root", 17);
    alerts.perf_submit(args, &a, sizeof(a));
    return 0;
}

/* ================================================================
 * 2. Rare / dangerous syscalls
 * ================================================================*/

/* ptrace — used by debuggers but also rootkits */
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct alert_t a = {};
    a.pid        = bpf_get_current_pid_tgid() >> 32;
    a.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    a.ts_ns      = bpf_ktime_get_ns();
    a.anom_type  = ANOM_RARE_SYSCALL;
    a.detail_u32 = args->request;   /* PTRACE_ATTACH, PTRACE_POKEDATA, etc. */
    bpf_get_current_comm(&a.comm, sizeof(a.comm));
    __builtin_memcpy(a.extra, "ptrace detected", 16);
    alerts.perf_submit(args, &a, sizeof(a));
    return 0;
}

/* memfd_create — in-memory file execution (fileless malware) */
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    struct alert_t a = {};
    a.pid       = bpf_get_current_pid_tgid() >> 32;
    a.uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    a.ts_ns     = bpf_ktime_get_ns();
    a.anom_type = ANOM_RARE_SYSCALL;
    bpf_get_current_comm(&a.comm, sizeof(a.comm));
    bpf_probe_read_user_str(a.extra, sizeof(a.extra), args->uname);
    alerts.perf_submit(args, &a, sizeof(a));
    return 0;
}

/* ================================================================
 * 3. File Open Storm (possible data exfiltration / directory scan)
 *    Alert if a single process opens > OPEN_RATE_THRESH files per window
 * ================================================================*/
#define OPEN_RATE_THRESH  100ULL
#define WINDOW_NS        (1000000000ULL)   /* 1 second window */

struct rate_val_t {
    u64 count;
    u64 window_start;
};

BPF_HASH(open_rate, u32, struct rate_val_t);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();

    struct rate_val_t zero = {};
    struct rate_val_t *rv = open_rate.lookup_or_try_init(&pid, &zero);
    if (!rv) return 0;

    /* Reset window if expired */
    if (now - rv->window_start > WINDOW_NS) {
        rv->count        = 0;
        rv->window_start = now;
    }
    rv->count++;

    if (rv->count == OPEN_RATE_THRESH) {   /* fire once per window */
        struct alert_t a = {};
        a.pid        = pid;
        a.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        a.ts_ns      = now;
        a.anom_type  = ANOM_FILE_STORM;
        a.detail_u32 = rv->count;
        bpf_get_current_comm(&a.comm, sizeof(a.comm));
        __builtin_memcpy(a.extra, "file open storm", 16);
        alerts.perf_submit(args, &a, sizeof(a));
    }
    return 0;
}

/* ================================================================
 * 4. Fork Bomb Detection
 * ================================================================*/
#define FORK_RATE_THRESH  50ULL

BPF_HASH(fork_rate, u32, struct rate_val_t);

TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();

    struct rate_val_t zero = {};
    struct rate_val_t *rv = fork_rate.lookup_or_try_init(&pid, &zero);
    if (!rv) return 0;

    if (now - rv->window_start > WINDOW_NS) {
        rv->count        = 0;
        rv->window_start = now;
    }
    rv->count++;

    if (rv->count == FORK_RATE_THRESH) {
        struct alert_t a = {};
        a.pid        = pid;
        a.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        a.ts_ns      = now;
        a.anom_type  = ANOM_FORK_BOMB;
        a.detail_u32 = rv->count;
        bpf_get_current_comm(&a.comm, sizeof(a.comm));
        __builtin_memcpy(a.extra, "fork bomb suspected", 20);
        alerts.perf_submit(args, &a, sizeof(a));
    }
    return 0;
}

/* ================================================================
 * 5. New Destination IP (first-seen external connection)
 * ================================================================*/
BPF_HASH(seen_ips, u32, u8);          /* set of seen destination IPs */
BPF_HASH(sock_store_ad, u64, struct sock *);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    sock_store_ad.update(&pid_tgid, &sk);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skp = sock_store_ad.lookup(&pid_tgid);
    if (!skp) return 0;

    struct sock *sk = *skp;
    struct inet_sock *is = (struct inet_sock *)sk;
    u32 daddr = sk->__sk_common.skc_daddr;

    u8 zero = 0;
    u8 *seen = seen_ips.lookup(&daddr);
    if (!seen) {
        /* First time connecting to this IP — alert */
        seen_ips.update(&daddr, &zero);

        struct alert_t a = {};
        a.pid        = pid_tgid >> 32;
        a.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        a.ts_ns      = bpf_ktime_get_ns();
        a.anom_type  = ANOM_NEW_DEST_IP;
        a.detail_u32 = daddr;
        bpf_get_current_comm(&a.comm, sizeof(a.comm));
        __builtin_memcpy(a.extra, "first-seen dest IP", 19);
        alerts.perf_submit(ctx, &a, sizeof(a));
    }

    sock_store_ad.delete(&pid_tgid);
    return 0;
}

/* ================================================================
 * 6. Executable Memory Protection — mprotect(PROT_EXEC)
 * ================================================================*/
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    if (!(args->prot & 0x4)) return 0;   /* 0x4 = PROT_EXEC */

    struct alert_t a = {};
    a.pid       = bpf_get_current_pid_tgid() >> 32;
    a.uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    a.ts_ns     = bpf_ktime_get_ns();
    a.anom_type = ANOM_EXEC_MPROTECT;
    bpf_get_current_comm(&a.comm, sizeof(a.comm));
    __builtin_memcpy(a.extra, "mprotect(PROT_EXEC) detected", 29);
    alerts.perf_submit(args, &a, sizeof(a));
    return 0;
}

