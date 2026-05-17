# By🇭🇷PhonkAlphabet
/* By🇭🇷PhonkAlphabet */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u64 timestamp;
    u32 event_type;
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct tracepoint__syscalls__sys_enter_execve *args) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = 1; // EXECVE
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

int trace_open(struct tracepoint__syscalls__sys_enter_open *args) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = 2; // OPEN
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// XDP program for high-performance packet filtering
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

int xdp_prog_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return XDP_PASS;

    // In production, this would check a BPF map of blocked IPs
    return XDP_PASS;
}
