#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

/* Event types */
#define EVENT_EXEC 1
#define EVENT_EXIT 2
#define EVENT_OPEN_FILE 3
#define EVENT_CONNECT 4

/* Kernel event structure */
struct kernel_event {
    __u64 timestamp_ns;      /* nsec precision from bpf_ktime_get_ns() */
    __u32 type;              /* event type */
    __u32 pid;               /* process PID */
    __u32 ppid;              /* parent PID */
    __u32 uid;               /* user ID */
    __u32 gid;               /* group ID */
    char comm[TASK_COMM_LEN]; /* process name */
    
    /* Union for event-specific data */
    union {
        struct {
            char filename[MAX_FILENAME_LEN];
            __u32 argc;
        } exec;
        
        struct {
            __s32 exit_code;
        } exit;
        
        struct {
            char path[MAX_FILENAME_LEN];
            __u32 flags;
        } open;
        
        struct {
            __u32 daddr;      /* dest IPv4 */
            __u16 dport;      /* dest port (network order) */
        } connect;
    } data;
};

/* Ring buffer output */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* PID filter map (optional: for allowlisting specific agents) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10000);
} monitored_pids SEC(".maps");

/* Helper: get current task struct */
static __always_inline struct task_struct *get_current_task() {
    return (struct task_struct *)bpf_get_current_task();
}

/* Helper: read task_struct field safely */
static __always_inline int get_task_info(struct task_struct *task, __u32 *pid, __u32 *ppid, char *comm) {
    if (!task) return -1;
    
    /* Read PID via CO-RE */
    *pid = BPF_CORE_READ(task, struct_pos(task_struct, tgid), tgid);
    
    /* Read parent PID */
    struct task_struct *parent = BPF_CORE_READ(task, struct_pos(task_struct, real_parent), real_parent);
    *ppid = BPF_CORE_READ(parent, struct_pos(task_struct, tgid), tgid);
    
    /* Read comm (16 bytes) */
    bpf_probe_read_kernel_str(comm, TASK_COMM_LEN, &task->comm);
    
    return 0;
}

/* Tracepoint: sched/sched_process_exec */
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct kernel_event *event;
    struct task_struct *task;
    __u32 uid, gid;
    
    /* Allocate ring buffer entry */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 1;
    
    /* Basic info */
    event->timestamp_ns = bpf_ktime_get_ns();
    event->type = EVENT_EXEC;
    
    /* Get task info via CO-RE */
    task = get_current_task();
    get_task_info(task, &event->pid, &event->ppid, event->comm);
    
    /* UIDs/GIDs */
    __u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    
    /* Exec-specific: filename from tracepoint context */
    bpf_probe_read_kernel_str(event->data.exec.filename, MAX_FILENAME_LEN, ctx->filename);
    event->data.exec.argc = ctx-> argc;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Tracepoint: sched/sched_process_exit */
SEC("tracepoint/sched/sched_process_template")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct kernel_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 1;
    
    event->timestamp_ns = bpf_ktime_get_ns();
    event->type = EVENT_EXIT;
    event->pid = ctx->pid;
    event->ppid = ctx->ppid;
    event->uid = ctx->uid;
    event->gid = ctx->gid;
    bpf_probe_read_kernel_str(event->comm, TASK_COMM_LEN, ctx->comm);
    
    event->data.exit.exit_code = ctx->prio;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Kprobe: sys_openat */
SEC("kprobe/do_sys_openat2")
int trace_openat(struct pt_regs *ctx) {
    struct kernel_event *event;
    struct task_struct *task;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 1;
    
    event->timestamp_ns = bpf_ktime_get_ns();
    event->type = EVENT_OPEN_FILE;
    
    task = get_current_task();
    get_task_info(task, &event->pid, &event->ppid, event->comm);
    
    __u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    
    /* Read filename from 2nd arg (struct open_how *how)
       NOTE: This is simplified; real implementation would parse open_how struct */
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
