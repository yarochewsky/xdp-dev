#include <linux/bpf.h>
#include "include/bpf_helpers.h"


SEC("xdp/xdp_drop")
int xdp_pass(struct xdp_md* ctx)
{
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
