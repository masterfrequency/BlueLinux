/* By🇭🇷PhonkAlphabet */
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

// eBPF program for real-time kernel event monitoring
// Captures: execve, open, connect, mmap syscalls

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
    u64 timestamp;
    u32 event_type;  // 1=execve, 2=open, 3=connect, 4=mmap
};

BPF_PERF_OUTPUT(events);
BPF_HASH(syscall_cache, u64, struct event_t);

// Trace execve syscall
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = 1;  // execve
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), 
                             (void *)args->filename);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Trace open syscall
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = 2;  // open
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename),
                             (void *)args->filename);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Trace connect syscall (network)
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = 3;  // connect
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Detect process injection via mmap with PROT_EXEC
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u64 flags = args->flags;
    u64 prot = args->prot;
    
    // Check for suspicious mmap: PROT_READ | PROT_WRITE | PROT_EXEC
    if ((prot & 7) == 7 && (flags & MAP_ANONYMOUS)) {
        struct event_t event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        event.timestamp = bpf_ktime_get_ns();
        event.event_type = 4;  // suspicious mmap
        
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
