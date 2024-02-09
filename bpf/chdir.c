#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u32 pid;
    __u32 upid;
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
    event->pid = (u32)bpf_get_current_pid_tgid();
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy;
    bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &t->nsproxy);
    event->upid = 0;
    if (nsproxy) {
        struct pid_namespace *pid_ns;
        bpf_probe_read_kernel(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children);
        if (pid_ns) {
            unsigned int upid;
            bpf_probe_read_kernel(&upid, sizeof(upid), &pid_ns->pid_allocated);
            event->upid = (__u32)upid;
        }
    }
    const char *path = (const char *)ctx->filename;
    bpf_probe_read_str(event->path, sizeof(event->path), path);
    bpf_ringbuf_submit(event, 0);
    return 0;
}