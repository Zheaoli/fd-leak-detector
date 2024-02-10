#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u32 pid;
    __u8 path[256];
};

const struct event *unusedevent __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct sys_enter_chdir_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char *filename;
};

SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_enter_chdir(struct sys_enter_chdir_args *ctx) {
    if (!ctx){
        return 0;
    }
    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) {
        return 0;
    }
    event->pid = bpf_get_current_pid_tgid()>>32;
    const char *path = (const char *)ctx->filename;
    bpf_probe_read_str(event->path, sizeof(event->path), path);
    bpf_ringbuf_submit(event, 0);
    return 0;
}