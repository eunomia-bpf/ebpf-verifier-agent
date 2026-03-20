CLANG ?= clang
BPFTool ?= sudo bpftool
CFLAGS ?= -target bpf -O2 -g -I /usr/include
PIN ?= /sys/fs/bpf/stackoverflow-61945212

all: fixed.o prog.o

prog.o: prog.c
	$(CLANG) $(CFLAGS) -c $< -o $@

verify: prog.o
	$(BPFTool) -d prog load prog.o $(PIN)

fixed.o: fixed.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f prog.o fixed.o
