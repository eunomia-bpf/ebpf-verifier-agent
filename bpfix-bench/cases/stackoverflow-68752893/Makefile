CLANG ?= clang
BPFTool ?= sudo bpftool
CFLAGS ?= -target bpf -O2 -g -I /usr/include
PIN ?= /sys/fs/bpf/$(notdir $(CURDIR))

.PHONY: all verify replay-verify clean

all: prog.o

prog.o: prog.c
	$(CLANG) $(CFLAGS) -c $< -o $@

verify: prog.o
	$(BPFTool) -d prog load prog.o $(PIN)

replay-verify: prog.o
	rm -f replay-verifier.log
	$(BPFTool) -d prog load prog.o $(PIN) > replay-verifier.log 2>&1

clean:
	rm -f prog.o replay-verifier.log
