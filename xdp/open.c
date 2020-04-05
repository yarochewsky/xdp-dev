#include <linux/bpf.h>
#include <string.h>
#include <linux/limits.h>
#include <bpf/bpf_helpers.h>
#include <fcntl.h>

struct syscalls_enter_openat_args {
	__u64 __dont_touch;
	__u64 syscall_nr;
	__u64 dfd;
  __u64 filename_ptr;
	__u64 flags;
	__u64 mode;
};

struct bpf_map_def SEC("maps") enter_open_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = PATH_MAX,
	.max_entries = 1,
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_open_at(struct syscalls_enter_openat_args* ctx) {
	__u32 entry = 0;
	char* val = bpf_map_lookup_elem(&enter_open_map, &entry);;
	if (!val)  {
		return 0;
	}
	bpf_probe_read_str(val, PATH_MAX, (const char*) ctx->filename_ptr);;
	return 0;
}

char __license[] SEC("license") = "GPL";
