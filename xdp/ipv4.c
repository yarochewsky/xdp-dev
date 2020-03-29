#include <linux/bpf.h>
#include "include/bpf_helpers.h"
#include "include/bpf_map.h"

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

struct stats {
	__u32 count;
	__u64 size;
};

struct bpf_map_def SEC("maps/xdp_stats_map") xdp_stats_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32), // type of xdp action
	.value_size = sizeof(struct stats), // number of packets
	.max_entries = 256,
	.pinning = 2,
	.namespace = "globals",
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

	curr->count++;
	curr->size = 10;
	
	return XDP_PASS;	
}

char _licesnse[] SEC("license") = "GPL";
