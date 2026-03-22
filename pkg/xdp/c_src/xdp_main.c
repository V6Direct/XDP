// SPDX-License-Identifier: GPL-2.0
// DDoS Mitigation XDP Program - Production Ready
// Uses libbpf CO-RE, pinned maps under /sys/fs/bpf/ddos/

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

#include "xdp_maps.h"
#include "xdp_filters.h"

char LICENSE[] SEC("license") = "GPL";

/* ─── Main XDP entrypoint ───────────────────────────────── */
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    struct parse_ctx pc = {};
    int dropped     = 0;
    int syn_flood   = 0;
    int udp_amp     = 0;
    int icmp_flood  = 0;

    /* ── Check if mitigation is enabled ── */
    __u32 cfg_key = CFG_ENABLED;
    __u64 *enabled = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (enabled && *enabled == 0) {
        /* mitigation disabled – pass all */
        update_global(0, 0, 0, 0, 0);
        return XDP_PASS;
    }

    /* ── Parse IP layer ── */
    if (parse_ip(ctx, &pc) < 0) {
        /* Non-IPv4 traffic: pass (could be ARP, IPv6, etc.) */
        return XDP_PASS;
    }

    /* ── Whitelist check ── */
    if (is_whitelisted(pc.src_ip)) {
        update_global(pc.pkt_len, 0, 0, 0, 0);
        return XDP_PASS;
    }

    /* ── Blocked IP check ── */
    if (is_blocked(pc.src_ip)) {
        update_global(pc.pkt_len, 1, 0, 0, 0);
        return XDP_DROP;
    }

    /* ── Get per-IP stats ── */
    struct ip_stats *stats = get_or_create_stats(pc.src_ip);
    if (!stats) {
        /* Cannot track – pass conservatively */
        return XDP_PASS;
    }

    /* Update per-IP packet + byte counter */
    stats->total_packets++;
    stats->total_bytes += pc.pkt_len;

    /* ── Protocol-specific filtering ── */
    switch (pc.proto) {
    case IPPROTO_TCP:
        if (parse_tcp(&pc) < 0)
            goto pass;

        if (check_syn_flood(&pc, stats)) {
            syn_flood = 1;
            dropped   = 1;
            goto drop;
        }
        break;

    case IPPROTO_UDP:
        if (parse_udp(&pc) < 0)
            goto pass;

        if (check_udp_amp(&pc, stats)) {
            udp_amp = 1;
            dropped = 1;
            goto drop;
        }
        break;

    case IPPROTO_ICMP:
        if (parse_icmp(&pc) < 0)
            goto pass;

        /* Drop ICMP fragments (common in amplification).
         * 0x2000 = IP_MF (more fragments), 0x1FFF = IP_OFFMASK.
         * Raw values used: netinet/ip.h macros unavailable in BPF context. */
        if (pc.iph->frag_off & bpf_htons(0x2000 | 0x1FFF)) {
            dropped    = 1;
            icmp_flood = 1;
            goto drop;
        }

        if (check_icmp_rate(&pc, stats)) {
            icmp_flood = 1;
            dropped    = 1;
            goto drop;
        }
        break;

    default:
        break;
    }

pass:
    update_global(pc.pkt_len, 0, syn_flood, udp_amp, icmp_flood);
    return XDP_PASS;

drop:
    update_global(pc.pkt_len, 1, syn_flood, udp_amp, icmp_flood);
    return XDP_DROP;
}
