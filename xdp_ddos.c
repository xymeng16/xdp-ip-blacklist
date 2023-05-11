/*  XDP example: DDoS protection via IPv4 blacklist
 *
 *  Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 *  Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include "bpf_helpers.h"

enum {
	DDOS_FILTER_TCP = 0,
	DDOS_FILTER_UDP,
	DDOS_FILTER_MAX,
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

#define XDP_ACTION_MAX (XDP_TX + 1)
BPF_LPM_TRIE(blacklist, struct ipv4_lpm_key, u32, 100000);
BPF_TABLE("percpu_array", u32, long, verdict_cnt, XDP_ACTION_MAX);
BPF_TABLE("percpu_array", u32, u32, port_blacklist, 65536);
BPF_TABLE("percpu_array", u32, u64, port_blacklist_drop_count_tcp, 65536);
BPF_TABLE("percpu_array", u32, u64, port_blacklist_drop_count_udp, 65536);

static inline struct bpf_map_def *drop_count_by_fproto(int fproto)
{

	switch (fproto) {
	case DDOS_FILTER_UDP:
		return &port_blacklist_drop_count_udp;
		break;
	case DDOS_FILTER_TCP:
		return &port_blacklist_drop_count_tcp;
		break;
	}
	return NULL;
}

// TODO: Add map for controlling behavior

// #define DEBUG 1
#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                                    \
	({                                                                     \
		char ____fmt[] = fmt;                                          \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
	})
#else
#define bpf_debug(fmt, ...)                                                    \
	{                                                                      \
	}                                                                      \
	while (0)
#endif

/* Keeps stats of XDP_DROP vs XDP_PASS */
static __always_inline void stats_action_verdict(u32 action)
{
	u64 *value;

	if (action >= XDP_ACTION_MAX)
		return;

	// value = bpf_map_lookup_elem(&verdict_cnt, &action);
	value = verdict_cnt.lookup(&action);
	if (value)
		*value += 1;
}

/* Parse Ethernet layer 2, extract network layer 3 offset and protocol
 *
 * Returns false on error and non-supported ether-type
 */
static __always_inline bool parse_eth(struct ethhdr *eth, void *data_end,
				      u16 *eth_proto, u64 *l3_offset)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;
	bpf_debug("Debug: eth_type:0x%x\n", ntohs(eth_type));

	/* Skip non 802.3 Ethertypes */
	if (unlikely(ntohs(eth_type) < ETH_P_802_3_MIN))
		return false;

	/* Handle VLAN tagged packet */
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}
	/* Handle double VLAN tagged packet */
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = ntohs(eth_type);
	*l3_offset = offset;
	return true;
}

static __always_inline u32 parse_port(struct xdp_md *ctx, u8 proto, void *hdr)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udph;
	struct tcphdr *tcph;
	u32 *value;
	u32 *drops;
	u32 dport;
	u32 dport_idx;
	u32 fproto;

	switch (proto) {
	case IPPROTO_UDP:
		udph = hdr;
		if (udph + 1 > data_end) {
			bpf_debug("Invalid UDPv4 packet: L4off:%llu\n",
				  sizeof(struct iphdr) + sizeof(struct udphdr));
			return XDP_ABORTED;
		}
		dport = ntohs(udph->dest);
		fproto = DDOS_FILTER_UDP;
		break;
	case IPPROTO_TCP:
		tcph = hdr;
		if (tcph + 1 > data_end) {
			bpf_debug("Invalid TCPv4 packet: L4off:%llu\n",
				  sizeof(struct iphdr) + sizeof(struct tcphdr));
			return XDP_ABORTED;
		}
		dport = ntohs(tcph->dest);
		fproto = DDOS_FILTER_TCP;
		break;
	case IPPROTO_ICMP:
		return XDP_PASS;
	default:
		return XDP_PASS;
	}

	dport_idx = dport;
	// value = bpf_map_lookup_elem(&port_blacklist, &dport_idx);
	value = port_blacklist.lookup(&dport_idx);

	if (value) {
		if (*value & (1 << fproto)) {
			switch (fproto) {
			case DDOS_FILTER_UDP: {
				drops = port_blacklist_drop_count_udp.lookup(
				    &dport_idx);
				break; // will never reach
			}
			case DDOS_FILTER_TCP: {
				drops = port_blacklist_drop_count_tcp.lookup(
				    &dport_idx);
				break; // will never reach
			}
			default: {
				if (drops) {
					*drops += 1; /* Keep a counter for drop
							matches */
					return XDP_DROP;
				}
				break;
			}
			}
		}
	}
	return XDP_PASS;
}

static __always_inline int ipv4_match(__be32 addr, __be32 net, u8 prefixlen)
{
	if (prefixlen == 0)
		return 1;
	return !((addr ^ net) & htonl(~0UL << (32 - prefixlen)));
}

static __always_inline u32 parse_ipv4(struct xdp_md *ctx, u64 l3_offset)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph = data + l3_offset;
	u64 *value;
	u32 ip_src; /* type need to match map */

	/* Hint: +1 is sizeof(struct iphdr) */
	if (iph + 1 > data_end) {
		bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return XDP_ABORTED;
	}
	/* Extract key */
	ip_src = iph->saddr;
	// ip_src = ntohl(ip_src); // ntohl does not work for some reason!?!

	bpf_debug("Valid IPv4 packet: raw saddr:0x%x\n", ip_src);

	// value = bpf_map_lookup_elem(&blacklist, &ip_src);
	struct ipv4_lpm_key key = {
                .prefixlen = 32,
                .data = ip_src
        };
	value = blacklist.lookup(&key);
	if (value) {
		/* Don't need __sync_fetch_and_add(); as percpu map */
		*value += 1; /* Keep a counter for drop matches */
		return XDP_DROP;
	}

	// return parse_port(ctx, iph->protocol, iph + 1);
	return XDP_PASS;
}

static __always_inline int parse_ipv6(struct xdp_md *ctx, u64 l3_offset)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	uint64_t ihl_len = sizeof(struct ipv6hdr);
	uint64_t nexthdr;

	ip6h = data + l3_offset;
	if (ip6h + 1 > data_end) {
		bpf_debug("Invalid IPv6 packet: L3off:%llu\n", l3_offset);
		return XDP_ABORTED;
	}

	nexthdr = ip6h->nexthdr;

	if (nexthdr == IPPROTO_IPIP) {
		iph = data + l3_offset + ihl_len;
		if (iph + 1 > data_end)
			return 0;
		ihl_len += iph->ihl * 4;
		nexthdr = iph->protocol;
	} else if (nexthdr == IPPROTO_IPV6) {
		ip6h = data + l3_offset + ihl_len;
		if (ip6h + 1 > data_end)
			return 0;
		ihl_len += sizeof(struct ipv6hdr);
		nexthdr = ip6h->nexthdr;
	}

	// return parse_port(ctx, iph->protocol, iph + 1);
	return XDP_PASS;
}

static __always_inline u32 handle_eth_protocol(struct xdp_md *ctx,
					       u16 eth_proto, u64 l3_offset)
{
	switch (eth_proto) {
	case ETH_P_IP:
		return parse_ipv4(ctx, l3_offset);
		break;
	case ETH_P_IPV6: /* Not handler for IPv6 yet*/
		return parse_ipv6(ctx, l3_offset);
	case ETH_P_ARP: /* Let OS handle ARP */
			/* Fall-through */
	default:
		bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		return XDP_PASS;
	}
	return XDP_PASS;
}

int xdp_ip_blocker(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u16 eth_proto = 0;
	u64 l3_offset = 0;
	u32 action;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n", l3_offset,
			  eth_proto);
		return XDP_PASS; /* Skip */
	}
	bpf_debug("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);

	action = handle_eth_protocol(ctx, eth_proto, l3_offset);
	stats_action_verdict(action);
	return action;
}