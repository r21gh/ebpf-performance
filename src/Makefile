# Generate the skeleton of send_recv.bpf.c
# bpftool gen skeleton send_recv_ebpf.o > send_recv_ebpf.skel.h

clang -O2 -g -target bpf -c websocket.bpf.c -o websocket.o


gcc -o send_recv_user send_recv_user.c -lbpf -lelf


sudo ./send_recv_user
