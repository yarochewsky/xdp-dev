#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/ip.h>

#ifndef MAX_VLAN_DEPTH
#define MAX_VLAN_DEPTH 4
#endif


#define printt(fmt, ...)																			\
{																														\
	char __fmt[] = fmt; 																				\
	bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); 	\
}

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

static __always_inline int parse_eth_header(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (eth  + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_eth_vlan_header(struct hdr_cursor* hc, void* data_end, struct ethhdr** eth_hdr) {
	struct ethhdr* eth = hc->pos;
	if (hc->pos + sizeof(*eth) > data_end) return -1;
	hc->pos += sizeof(*eth);
	*eth_hdr = eth;
	int proto = eth->h_proto;

	if (is_vlan(proto)) {
		struct vlan_hdr* vlan = hc->pos;
		if (vlan + 1 > data_end) return -1;
		return vlan->h_vlan_encapsulated_proto;
	}
	return proto;
}

static __always_inline int parse_ipv4_header(struct hdr_cursor* hc, void* data_end, struct iphdr** ipv4_hdr) {
	struct iphdr* ipv4h = hc->pos;

	if (ipv4h + 1 > data_end) return -1;
	
	hc->pos = ipv4h + 1;
	*ipv4_hdr = ipv4h;

	return ipv4h->protocol;
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

	return icmp6h->icmp6_type;
}

static __always_inline int parse_icmp_header(struct hdr_cursor* hc, void* data_end, struct icmphdr** icmp_hdr) {
	struct icmphdr* icmph = hc->pos;

	if (icmph + 1 > data_end) return -1;

	hc->pos = icmph + 1;
	*icmp_hdr = icmph;

	return icmph->type;
}

SEC("filter")
int filer_func(struct xdp_md* ctx) {
	int pkt_type;
	void* data_end = (void*) (long) ctx->data_end;
	void* data = (void*) (long) ctx->data;

	struct ethhdr* eth_hdr;
	struct hdr_cursor hc = { .pos = data };

	pkt_type = parse_eth_vlan_header(&hc, data_end, &eth_hdr);
	if (pkt_type < 0) return XDP_DROP;
	if (pkt_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr* ipv6_hdr;
		pkt_type = parse_ipv6_header(&hc, data_end, &ipv6_hdr);
		printt("type is %d\n", pkt_type);
		if (pkt_type != IPPROTO_ICMPV6) return XDP_PASS;	
		struct icmp6hdr* icmp6_hdr;
		if (parse_icmp6_header(&hc, data_end, &icmp6_hdr) < 0) return XDP_PASS;
		if (bpf_htons(icmp6_hdr->icmp6_sequence) % 2 == 0) return XDP_DROP;
	} else {
		struct iphdr* ipv4_hdr;
 		pkt_type = parse_ipv4_header(&hc, data_end, &ipv4_hdr);
		printt("type is %d\n", pkt_type);
	 	if (pkt_type != IPPROTO_ICMP) return XDP_PASS;
  	struct icmphdr* icmp_hdr;
  	if (parse_icmp_header(&hc, data_end, &icmp_hdr) < 0) return XDP_PASS;
  	if (bpf_htons(icmp_hdr->un.echo.sequence) % 2 == 0) return XDP_DROP;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
