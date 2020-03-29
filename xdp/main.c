#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include <net/if.h>
#include <linux/if_link.h>

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

int find_map_fd(struct bpf_object* bpf_obj, const char* name) {
	struct bpf_map* map;
	int fd = -1;

	map = bpf_object__find_map_by_name(bpf_obj, name);
	if (!map) {
		fprintf(stderr, "could not find map\n");
	}
	return fd;
}

static void usage() {
	printf("usage: ./main <elf_filepath> <iface>\n");
}

int main(int argc, char** argv) {

	if (argc < 4) {
		usage();
		return -1;
	}

	char* elf = argv[1];
	char* iface = argv[2];	
	char* sec = argv[3];
	char* force = argv[4];
	
	int fd, err;
	struct bpf_object* obj;

	int flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

	
	int offload_index = 0;
	if (argc == 6) {
		if (flags & XDP_FLAGS_HW_MODE) {
			offload_index = atoi(argv[5]);
		}
	}

	err = load_xdp_object_file(elf, offload_index, &obj);
	if (err) {
		return -1;
	}

	struct bpf_program* prog = bpf_object__find_program_by_title(obj, sec);
	if (!prog) {
		fprintf(stderr, "err: finding sec %s\n", sec);
		return -1;
	}
	
	fd = bpf_program__fd(prog);
	if (fd <= 0) {
		fprintf(stderr, "err: getting program fd\n");
		return -1;
	}

	if (argc == 5 && strcmp(force, "--force") == 0) flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;

	int ifindex = if_nametoindex(iface);
	if (ifindex == 0) {
		fprintf(stderr, "interface does not exist %s\n", iface);
		return -1;
	}

	err = xdp_link_attach(ifindex, flags, fd);
	if (err) return err;

	printf("loaded %s into %s!\n", elf, iface);

	int map_fd = bpf_object__find_map_fd_by_name(obj, "xdp_stats_map");
	if (map_fd < 0) {
		xdp_link_detach(ifindex, flags);
		fprintf(stderr, "err: could not find map by name %s\n", "xdp_stats_map");
		return -1;
	}

	__u32 key = 2;
 	__u32 val;
	while(true) {
			if((bpf_map_lookup_elem(map_fd, &key, &val)) != 0) {
				fprintf(stderr, "err: looking up key: %d\n", key);
			} else {
				printf("val is %d\n", val);
			}
	}
	
	return 0;
}
