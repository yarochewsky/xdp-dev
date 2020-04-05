// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Facebook
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define printt(fmt, ...)																			\
{																														\
	char __fmt[] = fmt; 																				\
	bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); 	\
}


struct syscalls_enter_open_args {
	unsigned long long unused;
	long syscall_nr;
	long filename_ptr;
	long flags;
	long mode;
};

struct syscalls_exit_open_args {
	unsigned long long unused;
	long syscall_nr;
	long ret;
};

struct bpf_map_def SEC("maps") enter_open_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") exit_open_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

static __always_inline void count(void *map)
{
	__u32 key = 0;
	__u32 *value, init_val = 1;

	value = bpf_map_lookup_elem(map, &key);
	if (value)
		*value += 1;
	else
		bpf_map_update_elem(map, &key, &init_val, BPF_NOEXIST);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct syscalls_enter_open_args *ctx)
{
	count(&enter_open_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_open_at(struct syscalls_enter_open_args *ctx)
{
	printt("%s\n", "triggered");
  char buf[] = "Hello World!\n";
  bpf_trace_printk(buf, sizeof(buf));
	count(&enter_open_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_enter_exit(struct syscalls_exit_open_args *ctx)
{
	count(&exit_open_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_enter_exit_at(struct syscalls_exit_open_args *ctx)
{
	count(&exit_open_map);
	return 0;
}

char __license[] SEC("license") = "GPL";
