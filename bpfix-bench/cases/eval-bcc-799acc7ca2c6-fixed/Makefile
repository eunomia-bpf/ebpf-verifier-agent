.PHONY: all replay-verify verify clean

all: prog.o

prog.o: prog.c
	clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -I/usr/include -Iheaders/libbpf-tools/x86 -Iheaders/libbpf-tools -c prog.c -o prog.o

verify: replay-verify

replay-verify: prog.o
	rm -f replay-verifier.log
	sudo rm -rf /sys/fs/bpf/eval-bcc-799acc7ca2c6-fixed
	sudo bpftool -d prog loadall prog.o /sys/fs/bpf/eval-bcc-799acc7ca2c6-fixed > replay-verifier.log 2>&1

clean:
	rm -f prog.o replay-verifier.log
	sudo rm -rf /sys/fs/bpf/eval-bcc-799acc7ca2c6-fixed
