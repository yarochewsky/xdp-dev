UNAME=$(shell uname -r)
LINUX_HEADERS ?= /lib/modules/$(UNAME)
CLANG ?= clang
LLC ?= llc
SHELL=bash -o pipefail -e

CFLAGS =  -I ./include \
	-I $(LINUX_HEADERS)/build/arch/x86/include \
	-I $(LINUX_HEADERS)/build/arch/x86/include/generated/uapi \
	-I $(LINUX_HEADERS)/build/arch/x86/include/generated \
	-I $(LINUX_HEADERS)/build/include \
	-I $(LINUX_HEADERS)/build/arch/x86/include/uapi \
	-I $(LINUX_HEADERS)/build/include/uapi \
	-include $(LINUX_HEADERS)/build/include/linux/kconfig.h \
	-I $(LINUX_HEADERS)/build/include/generated/uapi \
	-D__KERNEL__ -D__ASM_SYSREG_H \
	-Wunused \
	-Wall \
	-Wno-compare-distinct-pointer-types \
	-fno-stack-protector \
	-Wno-pointer-sign \
	-O2 -S -emit-llvm

ELFS_DIR = elfs
SRC_DIR = src

OBJS = pass.o drop.o pass_drop.o

all: $(OBJS)

$(OBJS): %.o:%.c
	$(CLANG) $(CFLAGS) -c $< -o - | $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $(ELFS_DIR)/$@

.PHONY: clean
clean:
	rm -f $(ELFS_DIR)/$(OBJS)
