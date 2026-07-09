/* 
 * Silence macro redefinition warnings by undefining them before includes.
 */
#undef __HAVE_BUILTIN_BSWAP16__
#undef __HAVE_BUILTIN_BSWAP32__
#undef __HAVE_BUILTIN_BSWAP64__



/*
 * network_monitor.c
 * eBPF program to monitor network activity:
 *   - TCP connect / accept events with source/dest IP+port
 *   - Bytes sent and received per process
 *   - Connection duration tracking
 * Loaded by tools/network_monitor.py via BCC
 */

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>
#include <bcc/proto.h>

/* ---- Event types ---- */
#define EVT_CONNECT  1
#define EVT_ACCEPT   2
#define EVT_CLOSE    3
#define EVT_SEND     4
#define EVT_RECV     5

/* ---- Event structure ---- */
struct net_event_t {
    u32  pid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    u32  saddr;          /* source IPv4 */
    u32  daddr;          /* dest   IPv4 */
    u16  sport;
    u16  dport;
    u64  bytes;          /* for send/recv events */
    u64  ts_ns;
    u8   event_type;
};



BPF_PERF_OUTPUT(net_events);

/* Track sockets in-flight (connect entry → return) */
BPF_HASH(sock_store, u64, struct sock *);

/* Per-socket connection start time (for duration) */
BPF_HASH(conn_start, struct sock *, u64);

/* Cumulative bytes per pid */
BPF_HASH(tx_bytes, u32, u64);
BPF_HASH(rx_bytes, u32, u64);

/* ----------------------------------------------------------------
 * Helper: read IPv4 addresses from sock
 * ----------------------------------------------------------------*/
static void fill_addrs(struct net_event_t *e, struct sock *sk) {
    struct inet_sock *is = (struct inet_sock *)sk;
    e->saddr = is->inet_saddr;
    e->daddr = sk->__sk_common.skc_daddr;
    e->sport = is->inet_sport;
    e->dport = sk->__sk_common.skc_dport;
}

/* ================================================================
 * TCP Connect — outbound connections initiated by this host
 * ================================================================*/
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    sock_store.update(&pid_tgid, &sk);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) return 0;   /* ignore failed connects */

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skp = sock_store.lookup(&pid_tgid);
    if (!skp) return 0;

    struct net_event_t e = {};
    e.pid        = pid_tgid >> 32;
    e.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e.ts_ns      = bpf_ktime_get_ns();
    e.event_type = EVT_CONNECT;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    fill_addrs(&e, *skp);

    /* Store connection start for duration tracking */
    u64 ts = e.ts_ns;
    conn_start.update(skp, &ts);

    net_events.perf_submit(ctx, &e, sizeof(e));
    sock_store.delete(&pid_tgid);
    return 0;
}

/* ================================================================
 * TCP Accept — inbound connections
 * ================================================================*/
int trace_accept_return(struct pt_regs *ctx) {
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk) return 0;

    struct net_event_t e = {};
    e.pid        = bpf_get_current_pid_tgid() >> 32;
    e.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e.ts_ns      = bpf_ktime_get_ns();
    e.event_type = EVT_ACCEPT;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    fill_addrs(&e, newsk);

    u64 ts = e.ts_ns;
    conn_start.update(&newsk, &ts);

    net_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* ================================================================
 * TCP Send — track bytes transmitted
 * ================================================================*/
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                      struct msghdr *msg, size_t size) {
    u32  pid  = bpf_get_current_pid_tgid() >> 32;
    u64  zero = 0;
    u64 *val  = tx_bytes.lookup_or_try_init(&pid, &zero);
    if (val) lock_xadd(val, size);

    struct net_event_t e = {};
    e.pid        = pid;
    e.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e.ts_ns      = bpf_ktime_get_ns();
    e.event_type = EVT_SEND;
    e.bytes      = size;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    fill_addrs(&e, sk);

    net_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* ================================================================
 * TCP Receive — track bytes received
 * ================================================================*/
int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    /* Byte count captured at return */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    sock_store.update(&pid_tgid, &sk);
    return 0;
}

int trace_tcp_recvmsg_return(struct pt_regs *ctx) {
    int size = PT_REGS_RC(ctx);
    if (size <= 0) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 zero = 0;
    u64 *val = rx_bytes.lookup_or_try_init(&pid, &zero);
    if (val) lock_xadd(val, size);

    /* NEW: Submit event for the dashboard */
    struct sock **skp = sock_store.lookup(&pid_tgid);
    if (skp) {
        struct net_event_t e = {};
        e.pid        = pid;
        e.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        e.ts_ns      = bpf_ktime_get_ns();
        e.event_type = EVT_RECV;
        e.bytes      = size;
        bpf_get_current_comm(&e.comm, sizeof(e.comm));
        fill_addrs(&e, *skp);
        net_events.perf_submit(ctx, &e, sizeof(e));
        sock_store.delete(&pid_tgid);
    }

    return 0;
}
