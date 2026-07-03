/*
 * ipc.c - low-level IPC dispatch to the susfs kernel module.
 *
 * Two ABIs are supported: the prctl era (v1.5.2 - v1.5.12) and the v2.0.0+
 * sys_reboot syscall interface.
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "susfs.h"

int prctl_cmd(unsigned long cmd, void *arg) {
    int error = -1;
    prctl(KERNEL_SU_OPTION, cmd, arg, NULL, &error);
    return error;
}

int prctl_cmd_scalar(unsigned long cmd, unsigned long val) {
    int error = -1;
    prctl(KERNEL_SU_OPTION, cmd, val, NULL, &error);
    return error;
}

int prctl_cmd4(unsigned long cmd, void *arg3, unsigned long arg4) {
    int error = -1;
    prctl(KERNEL_SU_OPTION, cmd, arg3, (void *)arg4, &error);
    return error;
}

void v2000_cmd(unsigned long cmd, void *info) {
    syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, cmd, info);
}

void prt_not_supported(unsigned long cmd, int err) {
    bool unsupported = (g_abi == ABI_v2000)
                       ? (err == ERR_v2000_CMD_NOT_SUPPORTED)
                       : (err == -1);
    if (unsupported)
        printf("[-] CMD: '0x%lx', SUSFS operation not supported, please enable it in kernel\n", cmd);
}
