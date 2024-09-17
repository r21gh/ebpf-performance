#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/unistd.h>
#include <stdatomic.h>

#define RINGBUF_SZ 8192 // 8KB ring buffer
#define ID_TYPE_RECV 2
#define ID_TYPE_SEND 3

// Define the event structure to be
// sent to user space via the ring buffer.
struct event_t {
    u64 timestamp_ns;
    u64 id;                 // ID is now a 64-bit unsigned integer (max 2^53)
    u32 type;               // Type of message (e.g., 2 for recv, 3 for result)
    u64 pid;                // Process ID for identifying the message
    u64 fd;                 // File descriptor to track the socket
};

// Declare a BPF ring buffer to send events to user space
BPF_RINGBUF_OUTPUT(events, RINGBUF_SZ);  // Define an 8KB buffer

static __always_inline int read_msg(struct msghdr *msg, struct event_t *event) {
    // Ensure the message size is large enough to hold type and ID
    if (msg.msg_iov->iov_len < sizeof(event-type) + sizeof(event->id)) {
        return 0; // Message is too small
    }

    // Read the type and ID from the message
    // Type: 4 bytes, ID: 8 bytes
    bpf_probe_read(&event->type, sizeof(event->type), msg.msg_iov->iov_base);
    bpf_probe_read(&event->id, sizeof(event->id), msg->msg_iov->iov_base + sizeof(event->type));

    return 1; // Message read successfully
}

// Inline helper function to send event to the ring buffer
static __always_inline void submit_event(struct event_t *event) {
    // Check if the ring buffer is full
    if (events.ringbuf_capacity() - events.ringbuf_used() >= sizeof(*event)) {
        // Submit the event to the ring buffer
        events.ringbuf_output(event, sizeof(*event), 0);
    }
}

// Function to trace incoming websocket traffic (recv)
int trace_recv(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg, size_t size) {
    u64 ts_ns = bpf_ktime_get_ns(); // Get the current time in nanoseconds
    // Prepare the event structure for recv event
    struct event_t event = {};
    event.timestamp_ns = ts_ns;
    event.pid = bpf_get_current_pid_tgid(); // Get the current process ID
    event.fd = sock->file>f_inode->i_ino; // Get the file descriptor (socket inode number)

    // Read the message to get the type and ID, if available
    if (read_msg(msg, &event)) {
        event.type = ID_TYPE_RECV; // Set the type to 2 for recv
        submit_event(&event); // Submit the event to the ring buffer
    }

    return 0;
}

// Function to trace outgoing websocket traffic (send)
int trace_send(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg, size_t size) {
    u64 ts_ns = bpf_ktime_get_ns(); // Get the current time in nanoseconds

    // Prepare the event structure for send event
    struct event_t event = {};
    event.timestamp_ns = ts_ns;
    event.pid = bpf_get_current_pid_tgid(); // Get the current process ID
    event.fd = sock->file->f_inode->i_ino; // Get the file descriptor (socket inode number)

    // Read the message to get the type and ID, if available
    if (read_msg(msg, &event)) {
        event.type = ID_TYPE_SEND; // Set the type to 3 for send
        submit_event(&event); // Submit the event to the ring buffer
    }

    return 0;
}
