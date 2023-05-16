/*  XDP example: DDoS protection via IPv4 blacklist
 *
 *  Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 *  Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
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

struct ipv6_lpm_key {
	__u32 prefixlen;
    __u64 data[2]
};

#define DEBUG

BPF_LPM_TRIE(ipv4_whitelist, struct ipv4_lpm_key, u32, 100000);
BPF_LPM_TRIE(ipv6_whitelist, struct ipv6_lpm_key, u32, 100000);

// BPF_TABLE_PINNED("percpu_hash", u64, u64, ipv4_blocked, 100000,
// "/sys/fs/bpf/ipv4_blocked"); BPF_TABLE_PINNED("percpu_hash", u64, u64,
// ipv6_blocked, 100000, "/sys/fs/bpf/ipv4_blocked");
BPF_TABLE("percpu_hash", u32, u64, ipv4_blocked, 100000);
BPF_TABLE("percpu_hash", struct in6_addr, u64, ipv6_blocked, 100000);

#define fmt_valid_str "Valid IPv4 packet: saddr:0x%x\n"
#define fmt_v4_blocked_str "IPv4 not in the whitelist: saddr:0x%x\n"

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

static __always_inline u32 parse_port(struct xdp_md *ctx, u8 proto, void *hdr,
				      u32 ip_src)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udph;
	struct tcphdr *tcph;
	u32 *value;
	u32 *drops;
	u32 dport;
	u32 dport_idx;
	u32 fproto;
	u64 zero = 0, *val;

	switch (proto) {
	case IPPROTO_TCP: {
		tcph = hdr;
		if (tcph + 1 > data_end) {
			return XDP_ABORTED;
		}
		dport = ntohs(tcph->dest);
		if (dport == 80 || dport == 443) {
			val = ipv4_blocked.lookup_or_init(&ip_src, &zero);
			if (val) {
				*val += 1;
			}
			bpf_trace_printk(
			    "IPv4 not in the whitelist: saddr:0x%x\n", ip_src);
			return XDP_DROP;
		}
		break;
	}
#ifdef DEBUG
	case IPPROTO_ICMP: {
		bpf_trace_printk("Blocked ICMPv4 from 0x%x\n", ip_src);
		val = ipv4_blocked.lookup_or_init(&ip_src, &zero);
		if (val) {
			*val += 1;
            bpf_trace_printk("current value is %d\n", *val);
		}
		return XDP_DROP;
		break;
	}
#endif
	}

	return XDP_PASS;
}

static __always_inline u32 parse_ipv4(struct xdp_md *ctx, u64 l3_offset)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph = data + l3_offset;
	u32 *value, v2;
	u32 ip_src; /* type need to match map */

	/* Hint: +1 is sizeof(struct iphdr) */
	if (iph + 1 > data_end) {
		return XDP_ABORTED;
	}
	/* Extract key */
	ip_src = iph->saddr;
#ifdef DEBUG
	bpf_trace_printk("Valid IPv4 packet: saddr:0x%x\n", ip_src);
#endif
	struct ipv4_lpm_key key = {.prefixlen = 32, .data = ip_src};
	value = ipv4_whitelist.lookup(&key);
	if (value == NULL) { // not in the whitelist
		// check if is headed to 80/443
		return parse_port(ctx, iph->protocol, iph + 1, ip_src);
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
		return XDP_ABORTED;
	}

#ifdef DEBUG
    bpf_trace_printk("[1/2] Valid IPv6 packet from %08x %08x\n", ip6h->saddr.in6_u.u6_addr32[0], ip6h->saddr.in6_u.u6_addr32[1]);
    bpf_trace_printk("[2/2] Valid IPv6 packet from %08x %08x\n", ip6h->saddr.in6_u.u6_addr32[2], ip6h->saddr.in6_u.u6_addr32[3]);
#endif

    // for (int i = 0; i < 16; i++) {
    //     ip6_src[i] = ip6h->saddr.in6_u.u6_addr8[i];
    // }
    
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
        break;
	case ETH_P_ARP: /* Let OS handle ARP */
			/* Fall-through */
	default:
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
		return XDP_PASS; /* Skip */
	}

	action = handle_eth_protocol(ctx, eth_proto, l3_offset);
	return action;
}