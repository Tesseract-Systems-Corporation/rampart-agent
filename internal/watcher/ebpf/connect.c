//go:build ignore

// eBPF program to trace TCP connections
// Compiled with bpf2go

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// TCP states we care about
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_CLOSE       7

// Address families
#define AF_INET  2
#define AF_INET6 10

// Event types
#define EVENT_CONNECT 1
#define EVENT_CLOSE   2

// Connection event sent to userspace
struct conn_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 saddr_v4;
    __u32 daddr_v4;
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8  event_type;
    __u8  protocol;
    char  comm[16];
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} events SEC(".maps");

// Track connections we've seen (to avoid duplicates)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   // hash of connection tuple
    __type(value, __u8);  // 1 = seen
} seen_conns SEC(".maps");

// Hash a connection tuple for deduplication
static __always_inline __u64 hash_conn(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) ^ ((__u64)sport << 16) ^ dport;
}

// Tracepoint for TCP state changes - catches all TCP connections
SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Only trace TCP
    if (ctx->protocol != IPPROTO_TCP) {
        return 0;
    }

    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;

    // We care about:
    // 1. Connection established (SYN_SENT -> ESTABLISHED for outbound)
    // 2. Connection closed (any -> CLOSE)

    __u8 event_type = 0;

    if (oldstate == TCP_SYN_SENT && newstate == TCP_ESTABLISHED) {
        // Outbound connection established
        event_type = EVENT_CONNECT;
    } else if (newstate == TCP_CLOSE && oldstate == TCP_ESTABLISHED) {
        // Connection closed
        event_type = EVENT_CLOSE;
    } else {
        return 0;
    }

    __u16 family = ctx->family;
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    // Get port numbers
    __u16 sport = ctx->sport;
    __u16 dport = bpf_ntohs(ctx->dport);

    // Skip loopback and local connections for connect events
    if (event_type == EVENT_CONNECT) {
        if (family == AF_INET) {
            __u32 saddr = 0, daddr = 0;
            bpf_probe_read_kernel(&saddr, sizeof(saddr), ctx->saddr);
            bpf_probe_read_kernel(&daddr, sizeof(daddr), ctx->daddr);

            // Skip loopback (127.x.x.x)
            if ((daddr & 0xFF) == 127) {
                return 0;
            }
            // Skip same host
            if (saddr == daddr) {
                return 0;
            }

            // Deduplication
            __u64 conn_hash = hash_conn(saddr, daddr, sport, dport);
            __u8 seen = 1;
            if (bpf_map_lookup_elem(&seen_conns, &conn_hash)) {
                return 0; // Already seen
            }
            bpf_map_update_elem(&seen_conns, &conn_hash, &seen, BPF_ANY);
        }
    }

    // Allocate event in ring buffer
    struct conn_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->sport = sport;
    event->dport = dport;
    event->family = family;
    event->event_type = event_type;
    event->protocol = ctx->protocol;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Copy addresses
    if (family == AF_INET) {
        bpf_probe_read_kernel(&event->saddr_v4, sizeof(event->saddr_v4), ctx->saddr);
        bpf_probe_read_kernel(&event->daddr_v4, sizeof(event->daddr_v4), ctx->daddr);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(&event->saddr_v6, sizeof(event->saddr_v6), ctx->saddr_v6);
        bpf_probe_read_kernel(&event->daddr_v6, sizeof(event->daddr_v6), ctx->daddr_v6);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
