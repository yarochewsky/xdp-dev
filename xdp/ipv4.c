#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "headers/stats.h"

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif


struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32), // type of xdp action
	.value_size = sizeof(struct stats), // number of packets
	.max_entries = XDP_ACTION_MAX,
};

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp/ip_block")
int ip_block(struct xdp_md* ctx)
{
	__u32 key = XDP_PASS;
	struct stats* curr = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!curr) return XDP_ABORTED;

	void* end = (void*) (long) ctx->data_end;
	void* beg = (void*) (long) ctx->data;

	curr->count++;
	curr->bytes += (__u64) (end - beg);

	return XDP_PASS;	
}

char _licesnse[] SEC("license") = "GPL";
