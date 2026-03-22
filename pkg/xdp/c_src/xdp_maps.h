#ifndef XDP_MAPS_H
#define XDP_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

/* ─── Constants ─────────────────────────────────────────── */
#define MAX_TRACKED_IPS     65536
#define MAX_BLOCKED_IPS     4096
#define MAX_PREFIXES        256
#define SYN_RATE_LIMIT      1000   /* SYN packets/sec per IP before block */
#define UDP_RATE_LIMIT      5000   /* UDP packets/sec per IP before block */
#define ICMP_RATE_LIMIT     100    /* ICMP packets/sec per IP before block */
#define NS_PER_SEC          1000000000ULL
#define WINDOW_NS           1000000000ULL  /* 1 second sliding window */

/* ─── Per-IP tracking entry ─────────────────────────────── */
struct ip_stats {
    __u64 syn_count;
    __u64 udp_count;
    __u64 icmp_count;
    __u64 total_packets;
    __u64 total_bytes;
    __u64 window_start_ns;
    __u32 blocked;
    __u32 pad;
};

/* ─── Per-CPU global stats ──────────────────────────────── */
struct global_stats {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 dropped_packets;
    __u64 syn_floods;
    __u64 udp_amplifications;
    __u64 icmp_floods;
    __u64 passed_packets;
    __u64 pad;
};

/* ─── Blocked IP entry ──────────────────────────────────── */
struct blocked_entry {
    __u64 blocked_at_ns;
    __u32 reason;   /* 1=SYN, 2=UDP, 3=ICMP */
    __u32 pad;
};

/* ─── IP Prefix for whitelist/blacklist ─────────────────── */
struct ip_prefix {
    __u32 addr;
    __u32 prefixlen;
};

/* ─── BPF Maps ──────────────────────────────────────────── */

/* LRU hash: src_ip -> ip_stats (per-CPU for lock-free updates) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_TRACKED_IPS);
    __type(key, __u32);
    __type(value, struct ip_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_stats_map SEC(".maps");

/* Hash: src_ip -> blocked_entry */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __u32);
    __type(value, struct blocked_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

/* Per-CPU array: index 0 = global stats */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} global_stats_map SEC(".maps");

/* Hash: whitelisted IPs (value unused, presence = whitelisted) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACKED_IPS);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_map SEC(".maps");

/* Config map: index -> threshold value */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

/* Config map indices */
#define CFG_SYN_RATE    0
#define CFG_UDP_RATE    1
#define CFG_ICMP_RATE   2
#define CFG_ENABLED     3

#endif /* XDP_MAPS_H */
