CLANG ?= clang
CC ?= cc
PIN ?= /sys/fs/bpf/kernel-selftest-iters-iter-new-bad-arg-raw-tp-e25f0e76
TARGET_FUNCTION ?= iter_new_bad_arg

CLANG_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | awk '/#include <...> search starts here:/{flag=1; next} /End of search list./{flag=0} flag && $$1 ~ /^\// {printf "-idirafter %s ", $$1}')
CFLAGS := -g -Wall -Werror -Wno-unused-function -Wno-unused-variable -D__TARGET_ARCH_x86 -mlittle-endian -Iheaders -Iheaders/progs -std=gnu11 -fno-strict-aliasing -Wno-microsoft-anon-tag -fms-extensions -Wno-compare-distinct-pointer-types -Wno-initializer-overrides $(CLANG_SYS_INCLUDES) -O2 --target=bpfel -mcpu=v3

.PHONY: all verify clean

all: prog.o selftest_prog_loader

prog.o: prog.c
	$(CLANG) $(CFLAGS) -c $< -o $@

selftest_prog_loader: selftest_prog_loader.c
	$(CC) -O2 -Wall -Wextra -Werror $< -lbpf -lelf -lz -o $@

verify: prog.o selftest_prog_loader
	@sudo ./selftest_prog_loader prog.o $(TARGET_FUNCTION) > verifier_load_result.json
	@python3 - <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path("verifier_load_result.json").read_text())
verifier_log = data.get("verifier_log") or ""
pathlib.Path("verifier_log_captured.txt").write_text(verifier_log + ("\n" if verifier_log else ""), encoding="utf-8")
sys.exit(0 if data.get("load_ok") else 1)
PY

clean:
	rm -f prog.o selftest_prog_loader verifier_log_captured.txt verifier_load_result.json
