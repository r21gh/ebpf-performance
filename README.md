# WebSocket Monitoring with eBPF and Prometheus

This project provides a WebSocket monitoring solution using eBPF (Extended Berkeley Packet Filter) for real-time packet tracking and Prometheus for metrics collection and exposure. The setup includes an eBPF program for tracing WebSocket traffic and a userspace application that calculates turnaround times, counts packets, and serves metrics through Prometheus.

## Components

1. **eBPF Program**: Traces WebSocket traffic and tracks message IDs to calculate turnaround times.
2. **Userspace Application**: Loads the eBPF program, handles events, calculates metrics, and exposes them via a Prometheus HTTP endpoint.
3. **Makefile**: Automates the build process for the eBPF program and userspace application.

## Directory Structure

- `src/`: Contains the source code for eBPF programs and the userspace application.
    - `ebpf_websocket.c`: eBPF program for tracing WebSocket traffic.
    - `userspace_app.c`: Userspace application that loads the eBPF program and serves Prometheus metrics.
- `Makefile`: Build configuration for eBPF programs and userspace application.

## Build Instructions
```sh
make
sudo ./userspace_app
```


#### **Metrics**:
The Prometheus metrics exposed by the userspace application include:

* `turnaround_count`: Total number of message turnarounds.
* `turnaround_sum`: Sum of turnaround times in nanoseconds.
* `packet_send_count`: Total number of packets sent.
* `packet_recv_count`: Total number of packets received.
* `identical_packets_count`: Number of packets that are identical in both send and receive.

#### **Prometheus Setup**:

1. Add a Prometheus scrape configuration:
In your Prometheus configuration file, add the following job:
```yaml
scrape_configs:
- job_name: 'websocket_metrics'
  static_configs:
    - targets: ['localhost:8080']
```
2. **Reload Prometheus Configuration**:
Ensure Prometheus picks up the new configuration.

#### **Troubleshooting**:

* eBPF Program Errors: Check if the eBPF program is loaded correctly using bpftool.
* Metrics Not Appearing: Ensure the userspace application is running and check network connectivity to port 8080.