# Paths and tools
LIBBPF_DIR = /usr/local/libbpf
KERNEL_HEADERS_DIR = $(shell echo "/usr/src/linux-headers-$(shell uname -r)" | xargs)
INCLUDES = -I$(LIBBPF_DIR)/include/uapi -I$(LIBBPF_DIR)/include -I$(KERNEL_HEADERS_DIR)/include -I$(KERNEL_HEADERS_DIR)/arch/x86/include/uapi
CLANG = clang
CC = gcc

# Build flags
CFLAGS = -g -Wall
LIBBPF_CFLAGS := -I$(LIBBPF_DIR)/include -I$(LIBBPF_DIR)/src
LIBBPF_LDFLAGS := -L$(LIBBPF_DIR)/lib -lbpf -lelf -lz -lmicrohttpd -lglib-2.0

# Output directories
OBJ_DIR = obj
SRC_DIR = src

# Targets
BPF_OBJECTS = $(OBJ_DIR)/ebpf_websocket.o
USER_OBJECTS = $(OBJ_DIR)/userspace_app

# BPF target
$(BPF_OBJECTS): $(SRC_DIR)/ebpf_websocket.c
	mkdir -p $(OBJ_DIR)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 $(INCLUDES) -c $< -o $@

# Userspace target
$(USER_OBJECTS): $(SRC_DIR)/userspace_app.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LDFLAGS)

# All target
all: $(BPF_OBJECTS) $(USER_OBJECTS)

# Clean build files
clean:
	rm -rf $(OBJ_DIR)/*.o $(OBJ_DIR)/userspace_app

# Install dependencies (optional for users to run manually)
install-deps:
	sudo apt-get install build-essential -y
	sudo apt-get install libc6-dev -y
	sudo apt-get install gcc-multilib -y

	sudo apt-get install linux-headers-generic
	sudo apt-get install linux-headers-$(uname -r)
	sudo apt-get install libglib2.0-dev libmicrohttpd-dev libelf-dev libssl-dev clang llvm libbpf-dev libbpfcc-dev

# Set up libbpf (optional)
setup-libbpf:
	git clone git@github.com:libbpf/libbpf.git
	cd libbpf/src && make && sudo make install
