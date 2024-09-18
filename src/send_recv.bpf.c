#include <linux/bpf.h>         // Core BPF definitions
#include <linux/ptrace.h>      // For bpf_trace_event (syscall arguments)
#include <linux/types.h>       // For u32, u64
#include <bpf/bpf_helpers.h>   // For BPF helper functions
#include <linux/sched.h>       // For task_struct (if needed)
#include <linux/unistd.h>      // For syscall numbers (optional)
#include <linux/string.h>      // For string operations like bpf_probe_read

struct event {
    u32 pid;
    u64 timestamp;
    int fd;
    char direction[5];  // "send" or "recv"
    char data[256];
};

// Define the BPF ring buffer to send events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // Size of the buffer
} events SEC(".maps");

// Trace the send syscall
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_send(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Reserve space in the ring buffer for the event
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->timestamp = bpf_ktime_get_ns();  // Get the current timestamp
    e->fd = ctx->args[0];               // First argument is the file descriptor
    e->direction[0] = 's';              // Indicate 'send'

    // Read the data sent by the user
    bpf_probe_read_user(e->data, sizeof(e->data), (void *)ctx->args[1]);

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Trace the recv syscall
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recv(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Reserve space in the ring buffer for the event
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->timestamp = bpf_ktime_get_ns();  // Get the current timestamp
    e->fd = ctx->args[0];               // First argument is the file descriptor
    e->direction[0] = 'r';              // Indicate 'recv'

    // Read the received data
    bpf_probe_read_user(e->data, sizeof(e->data), (void *)ctx->args[1]);

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
