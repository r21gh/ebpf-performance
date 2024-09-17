#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <time.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>  // GHashTable for dynamic event tracking

// Define the same structure as in the eBPF code
struct event_t {
    __u64 timestamp_ns;
    __u64 id;
    __u32 type;
    __u64 pid;
    __u64 fd;
};

#define ID_TYPE_RECV 2
#define ID_TYPE_SEND 3
#define HTTP_PORT 8080

// Global metrics for Prometheus
static unsigned long long turnaround_count = 0;
static unsigned long long turnaround_sum = 0;  // Sum of turnaround times in nanoseconds
static unsigned long long packets_sent = 0;
static unsigned long long packets_recv = 0;
static unsigned long long identical_packets_count = 0;

// Structure to track turnaround times based on message IDs
struct msg_event {
    __u64 recv_timestamp_ns;
    __u64 send_timestamp_ns;
    bool recv_seen;  // Track if receive event is seen
};

// Use a hash table for dynamic tracking of message events
GHashTable *events_table;

// Initialize the hash table
static void init_events() {
    events_table = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, free);
}

// Callback function to handle ring buffer events
static int handle_event(void *ctx, void *data, size_t len) {
    struct event_t *event = (struct event_t *)data;
    __u64 *event_id = malloc(sizeof(__u64));  // Key for the hash table
    struct msg_event *msg_event;

    if (!event_id) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    *event_id = event->id;

    // Handle receive event
    if (event->type == ID_TYPE_RECV) {
        msg_event = malloc(sizeof(struct msg_event));
        if (!msg_event) {
            fprintf(stderr, "Memory allocation failed\n");
            free(event_id);
            return -1;
        }
        msg_event->recv_timestamp_ns = event->timestamp_ns;
        msg_event->send_timestamp_ns = 0;
        msg_event->recv_seen = true;  // Mark as receive event seen
        packets_recv++;  // Increment received packets count

        // Insert or update the event in the hash table
        struct msg_event *existing_event = g_hash_table_lookup(events_table, event_id);
        if (existing_event) {
            if (existing_event->recv_seen && existing_event->send_timestamp_ns > 0) {
                // Both send and receive events have been seen
                identical_packets_count++;  // Increment identical packets count
                turnaround_sum += existing_event->send_timestamp_ns - existing_event->recv_timestamp_ns;
                turnaround_count++;
                g_hash_table_remove(events_table, event_id);  // Clean up the hash table
            }
        } else {
            g_hash_table_insert(events_table, event_id, msg_event);
        }
    }

    // Handle send event
    if (event->type == ID_TYPE_SEND) {
        msg_event = g_hash_table_lookup(events_table, event_id);
        if (msg_event) {
            msg_event->send_timestamp_ns = event->timestamp_ns;
            if (msg_event->recv_seen) {
                // Both send and receive events have been seen
                __u64 turnaround_ns = msg_event->send_timestamp_ns - msg_event->recv_timestamp_ns;
                turnaround_sum += turnaround_ns;  // Add to total sum
                turnaround_count++;  // Increment count
                identical_packets_count++;  // Increment identical packets count
                g_hash_table_remove(events_table, event_id);  // Clean up the hash table
            }
            packets_sent++;  // Increment sent packets count
        } else {
            // If no corresponding receive event, create a new entry
            msg_event = malloc(sizeof(struct msg_event));
            if (!msg_event) {
                fprintf(stderr, "Memory allocation failed\n");
                free(event_id);
                return -1;
            }
            msg_event->recv_timestamp_ns = 0;
            msg_event->send_timestamp_ns = event->timestamp_ns;
            msg_event->recv_seen = false;  // Mark as receive event not seen
            g_hash_table_insert(events_table, event_id, msg_event);
            packets_sent++;  // Increment sent packets count
        }
        free(event_id);  // Free event_id since it was allocated
    }

    return 0;
}

// Prometheus metrics handler
static int metrics_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method, const char *version,
                           const char *upload_data, size_t *upload_data_size, void **ptr) {
    char metrics[2048];  // Adjust buffer size as needed
    double average_turnaround = (turnaround_count > 0) ? (double)turnaround_sum / turnaround_count : 0;

    snprintf(metrics, sizeof(metrics),
             "# HELP turnaround_sum Total turnaround time in nanoseconds\n"
             "# TYPE turnaround_sum counter\n"
             "turnaround_sum %llu\n"
             "# HELP turnaround_count Total number of turnarounds\n"
             "# TYPE turnaround_count counter\n"
             "turnaround_count %llu\n"
             "# HELP average_turnaround Average turnaround time in nanoseconds\n"
             "# TYPE average_turnaround gauge\n"
             "average_turnaround %.2f\n"
             "# HELP packets_sent Total number of packets sent\n"
             "# TYPE packets_sent counter\n"
             "packets_sent %llu\n"
             "# HELP packets_recv Total number of packets received\n"
             "# TYPE packets_recv counter\n"
             "packets_recv %llu\n"
             "# HELP identical_packets_count Total number of identical packets\n"
             "# TYPE identical_packets_count counter\n"
             "identical_packets_count %llu\n",
             turnaround_sum, turnaround_count, average_turnaround, packets_sent, packets_recv, identical_packets_count);

    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(metrics),
                                                                    (void*)metrics, MHD_RESPMEM_MUST_COPY);
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

// Start the HTTP server to expose Prometheus metrics
static struct MHD_Daemon *start_prometheus_server() {
    struct MHD_Daemon *daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, HTTP_PORT, NULL, NULL,
                                                 &metrics_handler, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "Failed to start Prometheus metrics server\n");
    }
    return daemon;
}

int main() {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    int map_fd;
    int err;

    // Initialize event tracking with hash table
    init_events();

    // Load the eBPF object file
    obj = bpf_object__open_file("obj/ebpf_websocket.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // Load and verify eBPF programs
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Find the ring buffer map
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ring buffer map\n");
        return 1;
    }

    // Set up the ring buffer to poll events from the kernel
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    // Start the Prometheus server
    struct MHD_Daemon *daemon = start_prometheus_server();
    if (!daemon) {
        return 1;
    }

    printf("Listening for events and serving metrics on port %d...\n", HTTP_PORT);

    // Poll the ring buffer for events
    while (1) {
        err = ring_buffer__poll(rb, 100 /* timeout in ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    // Clean up
    ring_buffer__free(rb);
    bpf_object__close(obj);
    g_hash_table_destroy(events_table);
    MHD_stop_daemon(daemon);

    return 0;
}
