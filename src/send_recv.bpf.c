#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

#define MAX_BUF_SIZE 256

// Event structure for sending to user space
struct event {
    u32 pid;
    u64 timestamp;
    int fd;
    char direction[5];  // "send" or "recv"
    char data[MAX_BUF_SIZE];
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB
} events SEC(".maps");

// Trace send syscall
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_send(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    // Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Populate the event structure
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->fd = ctx->args[0];
    __builtin_memcpy(e->direction, "send", 5);  // Set direction as "send"

    // Copy up to MAX_BUF_SIZE bytes from the send buffer (args[1])
    bpf_probe_read_user(e->data, sizeof(e->data), (void *)ctx->args[1]);

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// Trace recv syscall
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recv(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    // Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Populate the event structure
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->fd = ctx->args[0];
    __builtin_memcpy(e->direction, "recv", 5);  // Set direction as "recv"

    // Copy up to MAX_BUF_SIZE bytes from the recv buffer (args[1])
    bpf_probe_read_user(e->data, sizeof(e->data), (void *)ctx->args[1]);

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// License declaration
char LICENSE[] SEC("license") = "GPL";
