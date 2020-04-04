#include <linux/bpf.h>
#include <string.h>
#include <bpf/bpf_helpers.h>

struct syscalls_enter_open_args {
	unsigned long long dont_touch;
	long syscall_nr;
	long filename_ptr;
	long flags;
	long mode;
};

struct trace_entry {
         short unsigned int type;
         unsigned char flags;
         unsigned char preempt_count;
         int pid;
};

struct trace_event_raw_sys_enter {
          struct trace_entry ent;
          long int id;
          long unsigned int args[6];
          char __data[0];
};

struct args {
	char filename[256];
};


struct bpf_map_def SEC("maps") enter_open_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct args),
	.max_entries = 1024,
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_open_at(struct syscalls_enter_open_args* ctx) {
	char buf[] = "Hello daniel2\n";
	bpf_trace_printk(buf, sizeof(buf));
	__u64 pid = bpf_get_current_pid_tgid();	

	struct args a = {};
//	if (sizeof(buf) > sizeof(a.filename)) return -1;
 	const char* filename = (const char*) ctx->filename_ptr;	
//	if (strlen(filename) > sizeof(a.filename)) return -1;

	#pragma unroll
	for (int i = 0; i < sizeof(buf); i++) {	
		a.filename[i] = buf[i];
	}

	bpf_map_update_elem(&enter_open_map, &pid, &a, BPF_ANY);
	return 0;
}


char __license[] SEC("license") = "GPL";
