#ifndef XDP_FILTERS_H
#define XDP_FILTERS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include "xdp_maps.h"

/* ─── Packet parsing context ────────────────────────────── */
struct parse_ctx {
    void        *data;
    void        *data_end;
    struct ethhdr *eth;
    struct iphdr  *iph;
    __u32        src_ip;
    __u32        pkt_len;
    __u8         proto;
    /* L4 */
    struct tcphdr  *tcph;
    struct udphdr  *udph;
    struct icmphdr *icmph;
};

/* ─── Parse Ethernet + IP header ────────────────────────── */
static __always_inline int parse_ip(struct xdp_md *ctx, struct parse_ctx *pc)
{
    pc->data     = (void *)(long)ctx->data;
    pc->data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = pc->data;
    if ((void *)(eth + 1) > pc->data_end)
        return -1;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > pc->data_end)
        return -1;

    pc->eth     = eth;
    pc->iph     = iph;
    pc->src_ip  = iph->saddr;
    pc->proto   = iph->protocol;
    pc->pkt_len = bpf_ntohs(iph->tot_len);
    return 0;
}

/* ─── Parse TCP header ──────────────────────────────────── */
static __always_inline int parse_tcp(struct parse_ctx *pc)
{
    __u32 ip_hlen = pc->iph->ihl * 4;
    if (ip_hlen < 20)
        return -1;

    struct tcphdr *tcph = (struct tcphdr *)((void *)pc->iph + ip_hlen);
    if ((void *)(tcph + 1) > pc->data_end)
        return -1;

    pc->tcph = tcph;
    return 0;
}

/* ─── Parse UDP header ──────────────────────────────────── */
static __always_inline int parse_udp(struct parse_ctx *pc)
{
    __u32 ip_hlen = pc->iph->ihl * 4;
    if (ip_hlen < 20)
        return -1;

    struct udphdr *udph = (struct udphdr *)((void *)pc->iph + ip_hlen);
    if ((void *)(udph + 1) > pc->data_end)
        return -1;

    pc->udph = udph;
    return 0;
}

/* ─── Parse ICMP header ─────────────────────────────────── */
static __always_inline int parse_icmp(struct parse_ctx *pc)
{
    __u32 ip_hlen = pc->iph->ihl * 4;
    if (ip_hlen < 20)
        return -1;

    struct icmphdr *icmph = (struct icmphdr *)((void *)pc->iph + ip_hlen);
    if ((void *)(icmph + 1) > pc->data_end)
        return -1;

    pc->icmph = icmph;
    return 0;
}

/* ─── Get or create ip_stats entry ─────────────────────── */
static __always_inline struct ip_stats *get_or_create_stats(__u32 src_ip)
{
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    if (!stats) {
        struct ip_stats new_stats = {};
        new_stats.window_start_ns = bpf_ktime_get_ns();
        bpf_map_update_elem(&ip_stats_map, &src_ip, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    }
    return stats;
}

/* ─── Get rate threshold from config map ─────────────────── */
static __always_inline __u64 get_threshold(__u32 idx, __u64 default_val)
{
    __u64 *val = bpf_map_lookup_elem(&config_map, &idx);
    if (val && *val > 0)
        return *val;
    return default_val;
}

/* ─── Check if IP is whitelisted ────────────────────────── */
static __always_inline int is_whitelisted(__u32 ip)
{
    __u8 *v = bpf_map_lookup_elem(&whitelist_map, &ip);
    return v != NULL;
}

/* ─── Check if IP is blocked ────────────────────────────── */
static __always_inline int is_blocked(__u32 ip)
{
    struct blocked_entry *e = bpf_map_lookup_elem(&blocked_ips, &ip);
    return e != NULL;
}

/* ─── Block an IP with given reason ─────────────────────── */
static __always_inline void block_ip(__u32 ip, __u32 reason)
{
    struct blocked_entry entry = {
        .blocked_at_ns = bpf_ktime_get_ns(),
        .reason        = reason,
    };
    bpf_map_update_elem(&blocked_ips, &ip, &entry, BPF_ANY);
}

/* ─── Update global stats ───────────────────────────────── */
static __always_inline void update_global(__u64 bytes, int dropped,
                                          int syn_flood, int udp_amp,
                                          int icmp_flood)
{
    __u32 key = 0;
    struct global_stats *gs = bpf_map_lookup_elem(&global_stats_map, &key);
    if (!gs)
        return;

    gs->total_packets++;
    gs->total_bytes += bytes;
    if (dropped) {
        gs->dropped_packets++;
    } else {
        gs->passed_packets++;
    }
    if (syn_flood)  gs->syn_floods++;
    if (udp_amp)    gs->udp_amplifications++;
    if (icmp_flood) gs->icmp_floods++;
}

/* ─── SYN flood check ───────────────────────────────────── */
static __always_inline int check_syn_flood(struct parse_ctx *pc,
                                           struct ip_stats *stats)
{
    if (!(pc->tcph->syn) || pc->tcph->ack)
        return 0;  /* not a pure SYN */

    __u64 now   = bpf_ktime_get_ns();
    __u64 delta = now - stats->window_start_ns;

    if (delta >= WINDOW_NS) {
        /* new window */
        stats->syn_count      = 1;
        stats->window_start_ns = now;
        return 0;
    }

    stats->syn_count++;
    __u64 threshold = get_threshold(CFG_SYN_RATE, SYN_RATE_LIMIT);

    if (stats->syn_count > threshold) {
        stats->blocked = 1;
        block_ip(pc->src_ip, 1);
        return 1;
    }
    return 0;
}

/* ─── UDP amplification check ───────────────────────────── */
static __always_inline int check_udp_amp(struct parse_ctx *pc,
                                         struct ip_stats *stats)
{
    __u64 now   = bpf_ktime_get_ns();
    __u64 delta = now - stats->window_start_ns;

    if (delta >= WINDOW_NS) {
        stats->udp_count       = 1;
        stats->window_start_ns = now;
        return 0;
    }

    stats->udp_count++;
    __u64 threshold = get_threshold(CFG_UDP_RATE, UDP_RATE_LIMIT);

    /* Amplification check: large response to small port (DNS:53, NTP:123,
       Memcached:11211, SSDP:1900, SNMP:161) */
    __u16 dport = bpf_ntohs(pc->udph->dest);
    __u16 sport = bpf_ntohs(pc->udph->source);
    int is_amplification_port =
        (sport == 53  || sport == 123  || sport == 1900 ||
         sport == 161 || sport == 11211);

    if (is_amplification_port && pc->pkt_len > 512) {
        stats->udp_count += 10; /* weight amplified packets heavily */
    }

    if (stats->udp_count > threshold) {
        stats->blocked = 1;
        block_ip(pc->src_ip, 2);
        return 1;
    }
    return 0;
}

/* ─── ICMP rate limit check ─────────────────────────────── */
static __always_inline int check_icmp_rate(struct parse_ctx *pc,
                                           struct ip_stats *stats)
{
    __u64 now   = bpf_ktime_get_ns();
    __u64 delta = now - stats->window_start_ns;

    if (delta >= WINDOW_NS) {
        stats->icmp_count      = 1;
        stats->window_start_ns = now;
        return 0;
    }

    stats->icmp_count++;
    __u64 threshold = get_threshold(CFG_ICMP_RATE, ICMP_RATE_LIMIT);

    if (stats->icmp_count > threshold) {
        stats->blocked = 1;
        block_ip(pc->src_ip, 3);
        return 1;
    }
    return 0;
}

#endif /* XDP_FILTERS_H */
