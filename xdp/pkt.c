#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#ifndef ICMP_6
#define ICMP_6 58 // proto number on next header ipv6 pkt
#endif

#ifndef MAX_VLAN_DEPTH
#define MAX_VLAN_DEPTH 4
#endif

struct hdr_cursor {
	void* pos;
};


struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};


static __always_inline int is_vlan(__u16 h_proto) {
	return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_eth_header(struct hdr_cursor* hc, void* data_end, struct ethhdr** eth_hdr) {
	struct ethhdr* eth = hc->pos;
	int hdrsize = sizeof(*eth);

	if (hc->pos + hdrsize > data_end) return -1;

	int proto;
	struct vlan_hdr* vlan = hc->pos;

	#pragma unroll
	for (int i = 0; i < MAX_VLAN_DEPTH; i++) {
		if (!is_vlan(eth->h_proto)) break;
		if (vlan + 1 > data_end) break;
		proto = vlan->h_vlan_encapsulated_proto;
		vlan++;
	}

	hc->pos = vlan;
	*eth_hdr = eth;

	return proto;
}

static __always_inline int parse_ipv6_header(struct hdr_cursor* hc, void* data_end, struct ipv6hdr** ipv6_hdr) {
	struct ipv6hdr* ipv6h = hc->pos;

	if (ipv6h + 1 > data_end) return -1;
	
	hc->pos = ipv6h + 1;
	*ipv6_hdr = ipv6h;

	return ipv6h->nexthdr;
}

static __always_inline int parse_icmp6_header(struct hdr_cursor* hc, void* data_end, struct icmp6hdr** icmp6_hdr) {
	struct icmp6hdr* icmp6h = hc->pos;

	if (icmp6h + 1 > data_end) return -1;

	hc->pos = icmp6h + 1;
	*icmp6_hdr = icmp6h;

	return 0;
}

SEC("filter")
int filer_func(struct xdp_md* ctx) {
	int pkt_type;
	void* data_end = (void*) (long) ctx->data_end;
	void* data = (void*) (long) ctx->data;

	struct ethhdr* eth_hdr;
	struct hdr_cursor hc = { .pos = data };

	pkt_type = parse_eth_header(&hc, data_end, &eth_hdr);
	if (pkt_type != bpf_htons(ETH_P_IPV6)) return XDP_ABORTED;

	struct ipv6hdr* ipv6_hdr;
	pkt_type = parse_ipv6_header(&hc, data_end, &ipv6_hdr);

	if (pkt_type != bpf_htons(ICMP_6)) return XDP_PASS;
	
	struct icmp6hdr* icmp6_hdr;
	if (parse_icmp6_header(&hc, data_end, &icmp6_hdr) < 0) return XDP_PASS;

	if (bpf_htons(icmp6_hdr->icmp6_sequence) % 2 == 0) return XDP_ABORTED;
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
