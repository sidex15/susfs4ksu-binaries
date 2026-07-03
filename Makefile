# Makefile for the ksu_susfs universal userspace tool.
#
# The CI (.github/workflows/build.yml) cross-compiles with `zig cc` against the
# Android NDK sysroot. Those toolchain specifics are injected via the CC,
# TARGET and SYSROOT variables so this Makefile stays host/toolchain agnostic:
#
#   make CC="./zig/zig cc" TARGET=aarch64-linux \
#        SYSROOT=./android-ndk-r27d/toolchains/llvm/prebuilt/linux-x86_64/sysroot \
#        OUT=ksu_susfs_arm64
#
# A bare `make` uses the host cc (handy for local syntax/build checks on Linux).

OUT     ?= ksu_susfs
TARGET  ?=
SYSROOT ?=

# `zig cc` takes -target; plain clang/gcc do not, so TARGET is optional.
TARGET_FLAG := $(if $(TARGET),-target $(TARGET),)
SYSROOT_INC := $(if $(SYSROOT),-I $(SYSROOT)/usr/include,)

CFLAGS  ?= -Oz -Wall
CFLAGS  += -Iinclude
LDFLAGS ?= -static -s -Wl,--gc-sections

# All translation units. main.c lives at the repo root; the rest under src/.
SRCS := main.c \
        src/ipc/ipc.c \
        src/detect/version.c \
        src/util/util.c \
        src/help/help.c \
        src/commands/commands.c

.PHONY: all clean

all: $(OUT)

# Single-shot compile+link. Cross toolchains (zig cc) prefer building all
# sources in one invocation over managing per-object files.
$(OUT): $(SRCS) include/susfs.h
	$(CC) $(TARGET_FLAG) $(CFLAGS) $(SRCS) $(LDFLAGS) $(SYSROOT_INC) -o $(OUT)

clean:
	rm -f $(OUT)
