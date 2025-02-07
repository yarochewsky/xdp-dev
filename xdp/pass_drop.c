#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp/xdp_pass")
int xdp_pass(struct xdp_md* ctx)
{
	return XDP_PASS;
}

SEC("xdp/xdp_drop")
int xdp_drop(struct xdp_md* ctx)
{
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
