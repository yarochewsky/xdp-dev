#include "loader.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>


int load_xdp_object_file(const char* filename, int ifindex, struct bpf_object** obj) {
	int fd = -1;
	int err;

	struct bpf_prog_load_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.ifindex = ifindex,
		.file = filename,
	};

	err = bpf_prog_load_xattr(&attr, obj, &fd);
	if (err) {
		fprintf(stderr, "err: loading ebpf object file(%s): %s\n", filename, strerror(-err));
		return -1;
	}
	return 0;	
}

int xdp_link_detach(int ifindex, __u32 xdp_flags) {
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "err: setting xdp unload failed: %s\n", strerror(-err));
		return -1;
	}
	return 0;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int fd) {
	int err;

	err = bpf_set_link_xdp_fd(ifindex, fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		__u32 old_flags = xdp_flags;
		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err) {
			err = bpf_set_link_xdp_fd(ifindex, fd, old_flags);
		}
	}

	if (err < 0) {
		fprintf(stderr, "err: ifindex(%d) link set xdp fd failed: %s\n", ifindex, strerror(-err));
		switch (-err) {
			case EBUSY:
			case EEXIST:
				fprintf(stderr, "xdp already loaded\n");
			case EOPNOTSUPP:
				fprintf(stderr, "native xdp not supported\n");
			default:
				break;
		}
		return -1;
	}
	return 0;
}

