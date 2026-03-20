CLANG ?= clang
BPFTool ?= sudo bpftool
CFLAGS ?= -target bpf -O2 -g -I /usr/include
PIN ?= /sys/fs/bpf/github-facebookincubator-katran-149

all: prog.o

prog.o: prog.c
	$(CLANG) $(CFLAGS) -c $< -o $@

verify: prog.o
	$(BPFTool) -d prog load prog.o $(PIN)

clean:
	rm -f prog.o fixed.o
