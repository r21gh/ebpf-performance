#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include "send_recv_ebpf.skel.h"  // Skeleton generated by bpftool

static volatile bool exiting = false;

#define MAX_ID 1024

// Structure for tracking packet times
struct packet_info {
    u64 timestamp;
    int direction;  // 2 for CALL, 3 for CALLRESULT
};

// Map to store packet timestamps by ID
struct packet_map {
    struct packet_info packets[MAX_ID];
};

// Event structure
struct event {
    u32 pid;
    u64 timestamp;
    int fd;
    char direction[5];  // "send" or "recv"
    char data[256];
};

// Storage for packet information
struct packet_map packet_storage;

// Variables to store the sum of turnaround times and packet count
u64 total_turnaround_time = 0;
int packet_count = 0;

// Event handler to process ring buffer events
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct event *e = data;
    u64 turnaround_time;
    int id;

    // Extract the ID from the packet data
    // Modify this part based on the actual format of your packet data
    sscanf(e->data, "%d", &id);

    if (e->direction[0] == 's') {  // send (CALL)
        // Save the send timestamp and direction
        packet_storage.packets[id].timestamp = e->timestamp;
        packet_storage.packets[id].direction = 2;  // CALL
    } else if (e->direction[0] == 'r') {  // recv (CALLRESULT)
        // Check if we have a corresponding send packet with the same ID
        if (packet_storage.packets[id].direction == 2) {  // CALL exists
            // Calculate the turnaround time
            turnaround_time = e->timestamp - packet_storage.packets[id].timestamp;
            printf("ID: %d, Turnaround Time: %llu ns\n", id, turnaround_time);

            // Add to total turnaround time and increment packet count
            total_turnaround_time += turnaround_time;
            packet_count++;

            // Reset the packet entry after processing (optional)
            packet_storage.packets[id].direction = 0;
            packet_storage.packets[id].timestamp = 0;
        }
    }
}

// Signal handler for graceful shutdown
void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct send_recv_ebpf *skel;
    int err;

    // Initialize packet storage
    memset(&packet_storage, 0, sizeof(packet_storage));

    // Load and attach the BPF program
    skel = send_recv_ebpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = send_recv_ebpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    // Set up signal handler for graceful shutdown
    signal(SIGINT, sig_handler);

    // Poll the ring buffer for events
    while (!exiting) {
        err = bpf_ring_buffer_poll(skel->maps.events, 100 /* timeout in ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // After exiting, calculate and print the average turnaround time
    if (packet_count > 0) {
        u64 average_turnaround_time = total_turnaround_time / packet_count;
        printf("Total Packets Processed: %d\n", packet_count);
        printf("Average Turnaround Time: %llu ns\n", average_turnaround_time);
    } else {
        printf("No matching packets found for calculating turnaround time.\n");
    }

    // Cleanup
    send_recv_ebpf__destroy(skel);
    return 0;
}
