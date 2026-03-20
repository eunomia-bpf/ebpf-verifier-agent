COMMON_CFLAGS := -target bpf -O2 -g -D__TARGET_ARCH_x86 -I/usr/include
BUGGY_INCLUDE_FLAGS := -I$(CURDIR)/headers/buggy/libbpf-tools/x86 -I$(CURDIR)/headers/buggy/libbpf-tools
FIXED_INCLUDE_FLAGS := -I$(CURDIR)/headers/fixed/libbpf-tools/x86 -I$(CURDIR)/headers/fixed/libbpf-tools
LOAD_PREFIX := sudo bpftool -d prog loadall
LOAD_SUFFIX :=

            .PHONY: all clean verify-buggy verify-fixed

            all: buggy.o fixed.o

            buggy.o: buggy.c
            	clang $(COMMON_CFLAGS) $(BUGGY_INCLUDE_FLAGS) -c $< -o $@

            verify-buggy: buggy.o
            	sudo rm -rf /sys/fs/bpf/eval-bcc-f6c8cfe4244a_buggy
            	$(LOAD_PREFIX) $< /sys/fs/bpf/eval-bcc-f6c8cfe4244a_buggy $(LOAD_SUFFIX)
            	sudo rm -rf /sys/fs/bpf/eval-bcc-f6c8cfe4244a_buggy

            fixed.o: fixed.c
	clang $(COMMON_CFLAGS) $(FIXED_INCLUDE_FLAGS) -c $< -o $@

verify-fixed: fixed.o
	sudo rm -rf /sys/fs/bpf/eval-bcc-f6c8cfe4244a_fixed
	$(LOAD_PREFIX) $< /sys/fs/bpf/eval-bcc-f6c8cfe4244a_fixed $(LOAD_SUFFIX)
	sudo rm -rf /sys/fs/bpf/eval-bcc-f6c8cfe4244a_fixed
clean:
            	rm -f buggy.o fixed.o
