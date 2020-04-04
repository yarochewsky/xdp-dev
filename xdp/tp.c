#define _GNU_SOURCE

#include <stdio.h>

#include <errno.h>
#include <stdlib.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <unistd.h>
    #include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>  

    #include <sys/syscall.h>

    #include <linux/perf_event.h>

#include "loader/loader.h"
#include "headers/stats.h"
#include "headers/bpf_util.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int filename__read_int(const char *filename, int *value)
{
	char line[64];
	int fd = open(filename, O_RDONLY), err = -1;

	if (fd < 0)
		return -1;

	if (read(fd, line, sizeof(line)) > 0) {
		*value = atoi(line);
		err = 0;
	}

	close(fd);
	return err;
}

static void usage() {
	printf("usage: ./main <elf_filepath> <sec>\n");
}

#define TP "/sys/kernel/debug/tracing/events/"

static int read_tp_id(const char *name, int *id)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, TP "%s/id", name);
	return filename__read_int(path, id);
}

int main(int argc, char** argv) {

	if (argc < 3) {
		usage();
		return -1;
	}

	char* elf = argv[1];
	char* sec = argv[2];

	int fd, err;
	struct bpf_object* obj;
	
	err = load_ebpf_tracepoint_file(elf, &obj);
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

	printf("loaded %s!\n", elf);

//	if ((err = pin_object_map(obj, "/sys/fs/bpf", "xdp_stats_map")) != 0) {
//		fprintf(stderr, "err: pinning map\n");
//		xdp_link_detach(ifindex, flags);
//		return -1;
//	}
//

	int id;
	if (read_tp_id("syscalls/sys_enter_openat", &id)) {
		fprintf(stderr, "err: could not read tp id: %s\n", strerror(errno));
		return -1;
	}	
 
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.config = id;
	attr.sample_period = 1;
//int efd = syscall(SYS_perf_event_open, &pattr, -1, 0, -1, 0);
int efd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
if (efd < 0)
{
printf("perf_event_open error: %s\n", strerror(errno));
exit(-1);
}
int ret = ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
if (ret < 0)
{
printf("PERF_EVENT_IOC_ENABLE error: %s\n", strerror(errno));
exit(-1);
}
ret = ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);
if (ret < 0)
{
printf("PERF_EVENT_IOC_SET_BPF error: %s\n", strerror(errno));
exit(-1);
}

	int map_fd = bpf_object__find_map_fd_by_name(obj, "enter_open_map");
	if (map_fd < 0) {
		fprintf(stderr, "err: could not find map by name %s\n", "enter_open_map");
		return -1;
  }

__u64 key;
void* keyp = &key, *prev_keyp = NULL;

struct args {
	char filename[256];
};

struct args value = {};

while(1) {
		err = bpf_map_get_next_key(map_fd, prev_keyp, keyp);
		if (err) {
			if (errno == ENOENT) err = 0;
			else break;
		}
		if ((bpf_map_lookup_elem(map_fd, keyp, &value)) != 0) {
				fprintf(stderr,
					"ERR: bpf_map_lookup_elem failed key:0x%llx\n", key);
		}
		prev_keyp = keyp;
		printf("%s\n", value.filename);
}

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
