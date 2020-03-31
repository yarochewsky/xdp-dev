#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "loader/loader.h"
#include "headers/stats.h"
#include "headers/bpf_util.h"

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

//	if ((err = pin_object_map(obj, "/sys/fs/bpf", "xdp_stats_map")) != 0) {
//		fprintf(stderr, "err: pinning map\n");
//		xdp_link_detach(ifindex, flags);
//		return -1;
//	}
//
//	int map_fd = bpf_object__find_map_fd_by_name(obj, "xdp_stats_map");
//	if (map_fd < 0) {
//		xdp_link_detach(ifindex, flags);
//		fprintf(stderr, "err: could not find map by name %s\n", "xdp_stats_map");
//		return -1;
//	}
//
//	__u32 key = 2;
//	unsigned int n_cpus = bpf_num_possible_cpus();
// 	struct stats vals[n_cpus];
//
//	while(true) {
//			__u64 sum_pkts = 0;
//			__u64 sum_bytes = 0;
//			if((bpf_map_lookup_elem(map_fd, &key, vals)) != 0) {
//				fprintf(stderr, "err: looking up key: %d\n", key);
//			} else {
//				for (int i = 0; i < n_cpus; i++) {
//					sum_pkts += vals[i].count;
//					sum_bytes += vals[i].bytes;
//				}
//				printf("count is %llu, bytes is :%llu\n", sum_pkts, sum_bytes);
//			}
//	}
	
	return 0;
}
