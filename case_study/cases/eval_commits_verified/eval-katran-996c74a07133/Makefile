COMMON_CFLAGS := -target bpf -O2 -g -D__TARGET_ARCH_x86 -D__no_sanitize_or_inline=             	-include stddef.h -include stdbool.h -include stdint.h -include linux/types.h             	-I/usr/include             	-I/usr/src/linux-headers-$(shell uname -r)/include/uapi             	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include/generated/uapi             	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include/generated             	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include/uapi             	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include             	-I/usr/src/linux-headers-$(shell uname -r)/include
BUGGY_INCLUDE_FLAGS := -I$(CURDIR)/headers/buggy/katran/lib/bpf -I$(CURDIR)/headers/buggy/katran/lib/linux_includes
FIXED_INCLUDE_FLAGS := -I$(CURDIR)/headers/fixed/katran/lib/bpf -I$(CURDIR)/headers/fixed/katran/lib/linux_includes
LOAD_PREFIX := sudo bpftool -m -L -d prog loadall
LOAD_SUFFIX := type xdp

            .PHONY: all clean verify-buggy verify-fixed

            all: buggy.o fixed.o

            buggy.o: buggy.c
            	clang $(COMMON_CFLAGS) $(BUGGY_INCLUDE_FLAGS) -c $< -o $@

            verify-buggy: buggy.o
            	sudo rm -rf /sys/fs/bpf/eval-katran-996c74a07133_buggy
            	$(LOAD_PREFIX) $< /sys/fs/bpf/eval-katran-996c74a07133_buggy $(LOAD_SUFFIX)
            	sudo rm -rf /sys/fs/bpf/eval-katran-996c74a07133_buggy

            fixed.o: fixed.c
	clang $(COMMON_CFLAGS) $(FIXED_INCLUDE_FLAGS) -c $< -o $@

verify-fixed: fixed.o
	sudo rm -rf /sys/fs/bpf/eval-katran-996c74a07133_fixed
	$(LOAD_PREFIX) $< /sys/fs/bpf/eval-katran-996c74a07133_fixed $(LOAD_SUFFIX)
	sudo rm -rf /sys/fs/bpf/eval-katran-996c74a07133_fixed
clean:
            	rm -f buggy.o fixed.o
