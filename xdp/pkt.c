#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>


struct hdr_cursor {
	void* pos;
};


static __always_inline int parse_eth_header(struct hdr_cursor* hc, void* data_end, struct ethhdr** eth_hdr) {
	struct ethhdr* eth = hc->pos;
	int hdrsize = sizeof(*eth);

	if (hc->pos + hdrsize > data_end) return -1;

	hc->pos += hdrsize;
	*eth_hdr = eth;

	return eth->h_proto;
}

static __always_inline int parse_ipv6_header(struct hdr_cursor* hc, void* data_end, struct ipv6hdr** ipv6_hdr) {
	struct ipv6hdr* ipv6h = hc->pos;

	if (ipv6h + 1 > data_end) return -1;
	
	hc->pos = ipv6h + 1;
	*ipv6_hdr = ipv6h;

	return ipv6h->nexthdr;
}

SEC("filter")
int filer_func(struct xdp_md* ctx) {
	void* data_end = (void*) (long) ctx->data_end;
	void* data = (void*) (long) ctx->data;

	struct ethhdr* eth_hdr;
	struct hdr_cursor hc = { .pos = data };

	int pkt_type = parse_eth_header(&hc, data_end, &eth_hdr);
	if (pkt_type == bpf_htons(ETH_P_IPV6)) {
		return XDP_ABORTED;
	}

	struct ipv6hdr* ipv6_hdr;
	pkt_type = parse_ipv6_header(&hc, data_end, &ipv6_hdr);
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
