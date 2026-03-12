/*
 * ksu_susfs - Universal userspace tool for susfs kernel module
 *
 * Supports all susfs kernel versions v1.5.2 through v2.0.0 in a SINGLE binary.
 * The correct kernel ABI and feature set are detected at runtime by probing the
 * kernel before executing any command.
 *
 * Detection strategy:
 *   1. Try v2.0.0 ABI: syscall(SYS_reboot, MAGIC1, SUSFS_MAGIC, SHOW_VERSION, &st)
 *      -> success (st.err == 0) means v2.0.0 kernel
 *   2. Try prctl ABI: prctl(KERNEL_SU_OPTION, SHOW_VERSION, buf, NULL, &error)
 *      -> error == 0  means v1.5.3-v1.5.12; parse version string for exact version
 *      -> error == -1 means v1.5.2 (no show cmd)
 *
 * Version integers used internally:
 *   152, 153, 154, 158, 159, 1510, 1511, 1512, 2000
 *   (154 covers v1.5.4-v1.5.7; 1510 covers v1.5.10 and v1.5.11)
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/sysmacros.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <sys/syscall.h>

/*************************
 ** Constants / Opcodes **
 *************************/
#define TAG "ksu_susfs"

/* prctl-era (v1.5.2 - v1.5.12) magic */
#define KERNEL_SU_OPTION    0xDEADBEEF

/* v2.0.0 syscall magic */
#define KSU_INSTALL_MAGIC1  0xDEADBEEF
#define SUSFS_MAGIC         0xFAFAFAFA

/* Command opcodes - identical across all versions */
#define CMD_SUSFS_ADD_SUS_PATH                   0x55550
#define CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH     0x55551
#define CMD_SUSFS_SET_SDCARD_ROOT_PATH           0x55552
#define CMD_SUSFS_ADD_SUS_PATH_LOOP              0x55553
#define CMD_SUSFS_ADD_SUS_MOUNT                  0x55560
#define CMD_SUSFS_HIDE_SUS_MNTS                  0x55561  /* all_procs pre-v2, non_su_procs in v2 */
#define CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE  0x55562
#define CMD_SUSFS_ADD_SUS_KSTAT                  0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT               0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY       0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT                 0x55580
#define CMD_SUSFS_SET_UNAME                      0x55590
#define CMD_SUSFS_ENABLE_LOG                     0x555a0
#define CMD_SUSFS_SET_BOOTCONFIG                 0x555b0  /* v1.5.2/v1.5.3 name */
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG      0x555b0  /* v1.5.4+ name (same opcode) */
#define CMD_SUSFS_ADD_OPEN_REDIRECT              0x555c0
#define CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS  0x555d0
#define CMD_SUSFS_SHOW_VERSION                   0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES          0x555e2
#define CMD_SUSFS_SHOW_VARIANT                   0x555e3
#define CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE       0x555e4
#define CMD_SUSFS_IS_SUS_SU_READY                0x555f0
#define CMD_SUSFS_SUS_SU                         0x60000
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING        0x60010
#define CMD_SUSFS_ADD_SUS_MAP                    0x60020

/* v2.0.0 error sentinel */
#define ERR_v2000_CMD_NOT_SUPPORTED  255

/* Misc kernel constants */
#define SUSFS_MAX_LEN_PATHNAME   256
#ifndef __NEW_UTS_LEN
#define __NEW_UTS_LEN            64
#endif

/* sus_su modes */
#define SUS_SU_DISABLED       0
#define SUS_SU_WITH_OVERLAY   1   /* deprecated since v1.5.3 */
#define SUS_SU_WITH_HOOKS     2
#define SUS_SU_CONF_FILE_PATH "/data/adb/ksu/bin/sus_su_drv_path"

/***************************
 ** Runtime version state **
 ***************************/

/* ABI flavour detected at startup */
#define ABI_UNKNOWN  0
#define ABI_PRCTL    1   /* v1.5.2 - v1.5.12 */
#define ABI_v2000     2   /* v2.0.0+ */

static int g_abi     = ABI_UNKNOWN;
static int g_version = 0;   /* e.g. 152, 153, 154, 158, 159, 1510, 1511, 1512, 2000 */
static char *g_version_string = NULL; /* e.g. "v1.5.2", "v1.5.4", "v2.0.0" */

/* True when the running kernel supports the given minimum version integer. */
#define HAVE(v)  (g_version >= (v))

/***************************
 ** Struct definitions     **
 ** Both ABI layouts kept. **
 ***************************/

/* ------ prctl-era structs (v1.5.2 - v1.5.12) ------ */

struct sus_path_v1 {            /* v1.5.2/v1.5.3: no i_uid */
    unsigned long   target_ino;
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
};

struct sus_path_v154 {          /* v1.5.4+: adds i_uid */
    unsigned long   target_ino;
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
    unsigned int    i_uid;
};

struct sus_mount_v1 {
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
    unsigned long   target_dev;
};

struct sus_kstat_v1 {
    bool                is_statically;
    unsigned long       target_ino;
    char                target_pathname[SUSFS_MAX_LEN_PATHNAME];
    unsigned long       spoofed_ino;
    unsigned long       spoofed_dev;
    unsigned int        spoofed_nlink;
    long long           spoofed_size;
    long                spoofed_atime_tv_sec;
    long                spoofed_mtime_tv_sec;
    long                spoofed_ctime_tv_sec;
    long                spoofed_atime_tv_nsec;
    long                spoofed_mtime_tv_nsec;
    long                spoofed_ctime_tv_nsec;
    unsigned long       spoofed_blksize;
    unsigned long long  spoofed_blocks;
};

struct try_umount_v1 {
    char    target_pathname[SUSFS_MAX_LEN_PATHNAME];
    int     mnt_mode;
};

struct uname_v1 {
    char release[__NEW_UTS_LEN+1];
    char version[__NEW_UTS_LEN+1];
};

struct open_redirect_v1 {
    unsigned long   target_ino;
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
    char            redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
};

struct sus_su_v152 {            /* v1.5.2 only: full driver creation */
    int     mode;
    char    drv_path[256];
    int     maj_dev_num;
};

struct sus_su_v153 {            /* v1.5.3+ simplified */
    int     mode;
};

struct sus_map_v1 {             /* v1.5.12 */
    char    target_pathname[SUSFS_MAX_LEN_PATHNAME];
};

/* ------ v2.0.0 structs (all gain int err field) ------ */

struct sus_path_v2000 {
    unsigned long   target_ino;
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
    unsigned int    i_uid;
    int             err;
};

struct external_dir_v2000 {      /* set_android_data_root_path / set_sdcard_root_path */
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
    bool            is_inited;
    int             cmd;
    int             err;
};

struct sus_mount_v2000 {
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
    unsigned long   target_dev;
    int             err;
};

struct hide_sus_mnts_v2000 {
    bool            enabled;
    int             err;
};

struct umount_zygote_v2000 {
    bool            enabled;
    int             err;
};

struct sus_kstat_v2000 {
    bool                is_statically;
    unsigned long       target_ino;
    char                target_pathname[SUSFS_MAX_LEN_PATHNAME];
    unsigned long       spoofed_ino;
    unsigned long       spoofed_dev;
    unsigned int        spoofed_nlink;
    long long           spoofed_size;
    long                spoofed_atime_tv_sec;
    long                spoofed_mtime_tv_sec;
    long                spoofed_ctime_tv_sec;
    long                spoofed_atime_tv_nsec;
    long                spoofed_mtime_tv_nsec;
    long                spoofed_ctime_tv_nsec;
    unsigned long       spoofed_blksize;
    unsigned long long  spoofed_blocks;
    int                 err;
};

struct try_umount_v2000 {
    char    target_pathname[SUSFS_MAX_LEN_PATHNAME];
    int     mnt_mode;
    int     err;
};

struct uname_v2000 {
    char    release[__NEW_UTS_LEN+1];
    char    version[__NEW_UTS_LEN+1];
    int     err;
};

struct log_v2000 {
    bool    enabled;
    int     err;
};

struct spoof_cmdline_v2000 {
    char    fake_cmdline_or_bootconfig[8192];
    int     err;
};

struct open_redirect_v2000 {
    unsigned long   target_ino;
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
    char            redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
    int             err;
};

struct sus_map_v2000 {
    char    target_pathname[SUSFS_MAX_LEN_PATHNAME];
    int     err;
};

struct avc_log_v2000 {
    bool    enabled;
    int     err;
};

struct enabled_features_v2000 {
    char    enabled_features[8192];
    int     err;
};

struct variant_v2000 {
    char    susfs_variant[16];
    int     err;
};

struct version_v2000 {
    char    susfs_version[16];
    int     err;
};

/***************************
 ** Low-level IPC helpers **
 ***************************/

/* Dispatch a command via the prctl ABI; returns value written to *error (0=OK, -1=unsupported). */
static int prctl_cmd(unsigned long cmd, void *arg) {
    int error = -1;
    prctl(KERNEL_SU_OPTION, cmd, arg, NULL, &error);
    return error;
}

/* prctl variant for scalar (non-pointer) third argument */
static int prctl_cmd_scalar(unsigned long cmd, unsigned long val) {
    int error = -1;
    prctl(KERNEL_SU_OPTION, cmd, val, NULL, &error);
    return error;
}

/* prctl variant with explicit 4th arg (e.g. SHOW_ENABLED_FEATURES passes bufsize) */
static int prctl_cmd4(unsigned long cmd, void *arg3, unsigned long arg4) {
    int error = -1;
    prctl(KERNEL_SU_OPTION, cmd, arg3, (void *)arg4, &error);
    return error;
}

/* Dispatch a command via the v2.0.0 syscall ABI. */
static void v2000_cmd(unsigned long cmd, void *info) {
    syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, cmd, info);
}

/* Print unified "not supported" message. */
static void prt_not_supported(unsigned long cmd, int err) {
    bool unsupported = (g_abi == ABI_v2000)
                       ? (err == ERR_v2000_CMD_NOT_SUPPORTED)
                       : (err == -1);
    if (unsupported)
        printf("[-] CMD: '0x%lx', SUSFS operation not supported, please enable it in kernel\n", cmd);
}

/****************************
 ** Runtime version detect **
 ****************************/

/*
 * Parse "X.Y.Z" into internal version integer:
 *   1.5.2  -> 152,  1.5.9  -> 159,
 *   1.5.10 -> 1510, 1.5.11 -> 1510, 1.5.12 -> 1512
 *   2.0.0  -> 2000
 * Versions 1.5.4-1.5.7 are all treated as 154.
 */
static int parse_version_string(const char *s) {
    int ma = 0, mi = 0, pa = 0;
    if (sscanf(s, "v%d.%d.%d", &ma, &mi, &pa) != 3)
        return 0;
    if (ma == 2) return 2000;
    /* 1.5.x */
    if (pa >= 12) return 1512;
    if (pa >= 10) return 1510;   /* covers 1.5.10 and 1.5.11 */
    if (pa == 9)  return 159;
    if (pa == 8)  return 158;
    if (pa >= 4)  return 154;    /* covers 1.5.4 - 1.5.7 */
    if (pa == 3)  return 153;
    if (pa == 2)  return 152;
    return 154; /* safe fallback */
}

static void detect_susfs_version(void) {
    /* Phase 1: probe v2.0.0 ABI */
    struct version_v2000 v2 = {0};
    v2.err = ERR_v2000_CMD_NOT_SUPPORTED;
    syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_VERSION, &v2);
    if (!v2.err) {
        g_abi     = ABI_v2000;
        g_version = parse_version_string(v2.susfs_version);
        g_version_string = strdup(v2.susfs_version);
        return;
    }

    /* Phase 2: probe prctl ABI */
    char ver_buf[16];
    int error = -1;
    prctl(KERNEL_SU_OPTION, CMD_SUSFS_SHOW_VERSION, ver_buf, NULL, &error);
    if (!error) {
        g_abi     = ABI_PRCTL;
        g_version = parse_version_string(ver_buf);
        g_version_string = strdup(ver_buf);
        return;
    }

    /* Phase 3: no show cmd -> must be v1.5.2 */
    g_abi     = ABI_PRCTL;
    g_version = 152;
    g_version_string = strdup("v1.5.2");
}

/********************
 ** Utility helpers **
 ********************/

static void pre_check(void) {
    if (getuid() != 0) {
        printf("[-] Must run as root\n");
        exit(1);
    }
}

static int get_file_stat(const char *pathname, struct stat *sb) {
    return stat(pathname, sb) != 0;
}

static void copy_stat_to_kstat_v1(struct sus_kstat_v1 *k, const struct stat *sb) {
    k->spoofed_ino           = sb->st_ino;
    k->spoofed_dev           = sb->st_dev;
    k->spoofed_nlink         = sb->st_nlink;
    k->spoofed_size          = sb->st_size;
    k->spoofed_atime_tv_sec  = sb->st_atime;
    k->spoofed_mtime_tv_sec  = sb->st_mtime;
    k->spoofed_ctime_tv_sec  = sb->st_ctime;
    k->spoofed_atime_tv_nsec = sb->st_atimensec;
    k->spoofed_mtime_tv_nsec = sb->st_mtimensec;
    k->spoofed_ctime_tv_nsec = sb->st_ctimensec;
    k->spoofed_blksize       = sb->st_blksize;
    k->spoofed_blocks        = sb->st_blocks;
}

static void copy_stat_to_kstat_v2000(struct sus_kstat_v2000 *k, const struct stat *sb) {
    k->spoofed_ino           = sb->st_ino;
    k->spoofed_dev           = sb->st_dev;
    k->spoofed_nlink         = sb->st_nlink;
    k->spoofed_size          = sb->st_size;
    k->spoofed_atime_tv_sec  = sb->st_atime;
    k->spoofed_mtime_tv_sec  = sb->st_mtime;
    k->spoofed_ctime_tv_sec  = sb->st_ctime;
    k->spoofed_atime_tv_nsec = sb->st_atimensec;
    k->spoofed_mtime_tv_nsec = sb->st_mtimensec;
    k->spoofed_ctime_tv_nsec = sb->st_ctimensec;
    k->spoofed_blksize       = sb->st_blksize;
    k->spoofed_blocks        = sb->st_blocks;
}

/* Read a file into a malloc'd buffer (null-terminated). Caller must free(). */
static int read_file_to_buf(const char *path, char **out, long *out_size) {
    char abs[PATH_MAX];
    if (!realpath(path, abs)) { perror("realpath"); return 1; }
    FILE *f = fopen(abs, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); perror("malloc"); return 1; }
    if ((long)fread(buf, 1, (size_t)sz, f) != sz) {
        fclose(f); free(buf); perror("fread"); return 1;
    }
    buf[sz] = '\0';
    fclose(f);
    *out = buf;
    if (out_size) *out_size = sz;
    return 0;
}

/********************
 ** print_help      **
 ********************/
static void print_help(void) {
    printf("usage: %s <CMD> [CMD options]\n", TAG);
    printf("help: %s --help <CMD>  (for more details of a specific command)\n", TAG);
    if (g_abi != ABI_UNKNOWN)
        printf("  Detected kernel: susfs %s (ABI: %s)\n",
               g_version_string,
               g_abi == ABI_v2000 ? "sys_reboot" : "prctl");
    printf("\n  <CMD>:\n");
    printf("    add_sus_path </path>\n");
    if (HAVE(1510))
        printf("    add_sus_path_loop </path>\n");
    if (HAVE(158)) {
        printf("    set_android_data_root_path </path/to/Android/data>\n");
        printf("    set_sdcard_root_path </path/to/sdcard>\n");
    }
    if (HAVE(2000)) {
        printf("    add_sus_mount <mounted_path> (If CLI feature is supported)\n");
    }
    else {
        printf("    add_sus_mount <mounted_path>\n");
    }
    if (HAVE(158) && g_abi == ABI_PRCTL)
        printf("    hide_sus_mnts_for_all_procs <0|1>\n");
    if (g_abi == ABI_v2000)
        printf("    hide_sus_mnts_for_non_su_procs <0|1>\n");
    if (HAVE(1510))
        printf("    umount_for_zygote_iso_service <0|1>\n");
    printf("    add_sus_kstat_statically </path> <ino> <dev> <nlink> <size>"
           " <atime> <atime_nsec> <mtime> <mtime_nsec> <ctime> <ctime_nsec>"
           " <blocks> <blksize>  (pass 'default' for any field)\n");
    printf("    add_sus_kstat </path>\n");
    printf("    update_sus_kstat </path>\n");
    printf("    update_sus_kstat_full_clone </path>\n");
    printf("    add_try_umount </path> <mode>  (mode: 0=no flags, 1=MNT_DETACH)\n");
    if (HAVE(159) && g_abi == ABI_PRCTL)
        printf("    run_try_umount\n");
    printf("    set_uname <release> <version>  (pass 'default' for either)\n");
    printf("    enable_log <0|1>\n");
    if (g_version == 152 || g_version == 153)
        printf("    set_bootconfig </path/to/file>\n");
    if (HAVE(154))
        printf("    set_cmdline_or_bootconfig </path/to/file>\n");
    printf("    add_open_redirect </target> </redirect>\n");
    if (HAVE(1512))
        printf("    add_sus_map </path/to/library>\n");
    if (HAVE(1510))
        printf("    enable_avc_log_spoofing <0|1>\n");
    if (HAVE(153))
        printf("    show <version|enabled_features|variant>\n");
    if (g_abi == ABI_PRCTL)
        printf("    sus_su <0|2|show_working_mode>\n");
    printf("\n");
}

/********************
 ** print_more_help     **
 ********************/
static int print_more_help(const char *cmd) {
    if (strcmp(cmd, "add_sus_path") == 0 ) {
        printf("    add_sus_path </path/of/file_or_directory>\n");
        printf("      |--> Added path and all its sub-paths will be hidden for umounted app process from several syscalls\n");
        printf("      |--> Please be reminded that if the target path has upper mounts then make sure the proper layer is added, otherwise it may not be effective for the target process.\n");
        printf("      * Important Notes *\n");
        printf("      - Only effective for umounted process with uid >= 10000\n");
        printf("      - On susfs version v1.5.8 - early v2.0.0, to fix the leak of app path after /sdcard/Android/data from syscall, please run ksu_susfs set_android_data_root_path </path/of/sdcard/Android/data> first\n");
        printf("    Example: %s add_sus_path /data/local/tmp/main.jar\n", TAG);
        return 0;
    }
    if (strcmp(cmd, "add_sus_path_loop") == 0 ) {
        printf("    add_sus_path_loop </path/of/file_or_directory>\n");
        printf("      |--> The only difference to add_sus_path is that the added sus_path via this cli will be flagged as SUS_PATH again for the app process when it is being spawned by zygote and marked umounted\n");
        printf("      |--> Also it does not check if the path is existed or not, instead it checks for empty string only, so be careful what to add.\n");
        printf("      * Important Notes *\n");
        printf("      - Only effective for umounted process with uid >= 10000\n");
        printf("      - On susfs version v1.5.8 - early v2.0.0, this applies to regular path (not including path in /sdcard/) only\n");
        printf("    Example: %s add_sus_path_loop /data/local/tmp/main.jar\n", TAG);
        return 0;
    }
    if (strcmp(cmd, "set_android_data_root_path") == 0) {
    	printf("    set_android_data_root_path </root/dir/of/sdcard/Android/data>\n");
        printf("      |--> To fix the leak of app path after /sdcard/Android/data/ from syscall, first you need to tell the susfs kernel where is the actual path '/sdcard/Android/data' located, as it may vary on different phones\n");
        printf("      |--> Effective for no root access granted user apps only\n");
        return 0;
    }
    if (strcmp(cmd, "set_sdcard_root_path") == 0) {
        printf("    set_sdcard_root_path </root/dir/of/sdcard>\n");
        printf("      |--> To hide paths after /sdcard/, first you need to tell the susfs kernel where is the actual path '/sdcard' located, as it may vary on different phones\n");
        printf("      |--> Warning: All no root access granted user apps cannot see any sus paths in /sdcard/ unless you grant root access for the target app\n");
        return 0;
    }
    if (strcmp(cmd, "add_sus_mount") == 0 ) {
        printf("    add_sus_mount </path/of/mount_point>\n");
	    printf("      |--> Added mounted path will be hidden from /proc/self/[mounts|mountinfo|mountstats]\n");
	    printf("      |--> Please be reminded that the target path must be added after the bind mount or overlay operation, otherwise it won't be effective\n");
        printf("    Example: %s add_sus_mount /system/etc/hosts\n", TAG);
        return 0;
    }
    if (strcmp(cmd, "hide_sus_mnts_for_all_procs") == 0) {
        printf("      |--> 0 -> Do not hide sus mounts for all processes but only non ksu process\n");
        printf("      |--> 1 -> Hide all sus mounts for all processes no matter they are ksu processes or not\n");
        printf("      * Important Notes *\n");
        printf("      - It is set to 1 in kernel by default\n");
        printf("      - It is recommended to set to 0 after screen is unlocked, or during service.sh or boot-completed.sh stage, as this should fix the issue on some rooted apps that rely on mounts mounted by ksu process\n");
        return 0;
    }
    if (strcmp(cmd, "hide_sus_mnts_for_non_su_procs") == 0) {
        printf("      |--> 0 -> DO NOT hide sus mounts for non-su processes\n");
	    printf("      |--> 1 -> hide all sus mounts for non-su processes\n");
	    printf("      * Important Notes *\n");
	    printf("      - It is set to 0 in kernel by default\n");
	    printf("      - For ReZygisk without TreatWheel module, it is recommended to set to 1 in post-fs-data.sh to prevent zygote from caching the sus mounts in memory, and revert to 0 in boot-completed.sh stage, or keep it enabled if you want to keep them hidden from /proc/self/[mounts|mountinfo|mountstat] for non-su processes\n");
        return 0;
    }
    if (strcmp(cmd, "umount_for_zygote_iso_service") == 0) {
        printf("      |--> 0 -> Do not umount for zygote spawned isolated service process\n");
        printf("      |--> 1 -> Enable to umount for zygote spawned isolated service process\n");
        printf("      * Important Notes *\n");
        printf("      - By default it is set to 0 in kernel, or create '/data/adb/susfs_umount_for_zygote_iso_service' to set it to 1 on boot\n");
        printf("      - Set to 0 if you have modules that overlay framework system files like framework.jar or other overlay apk, then atm you should let other module like zygisk and its hiding module to take care of, otherwise it may cause bootloop\n");
        printf("      - Set to 1 if you DO NOT have such modules mentioned above, otherwise sus mounts won't be umounted for zygote spawned isolated process and they will be detected\n");
        return 0;
    }
    if (strcmp(cmd, "add_sus_kstat_statically") == 0) {
        printf("    add_sus_kstat_statically </path> <ino> <dev> <nlink> <size>"
               " <atime> <atime_nsec> <mtime> <mtime_nsec> <ctime> <ctime_nsec>"
               " <blocks> <blksize>\n");
        printf("      |--> Use 'stat' tool to find the format:\n");
        printf("               ino -> %%i, dev -> %%d, nlink -> %%h, atime -> %%X, mtime -> %%Y, ctime -> %%Z\n");
        printf("               size -> %%s, blocks -> %%b, blksize -> %%B\n");
        printf("      |--> e.g., %s add_sus_kstat_statically '/system/addon.d' '1234' '1234' '2' '223344'\\\n", TAG);
        printf("                    '1712592355' '0' '1712592355' '0' '1712592355' '0' '1712592355' '0'\\\n");
        printf("                    '16' '512'\n");
        printf("      |--> Or pass 'default' to use its original value:\n");
        printf("      |--> e.g., %s add_sus_kstat_statically '/system/addon.d' 'default' 'default' 'default' 'default'\\\n", TAG);
        printf("                    '1712592355' 'default' '1712592355' 'default' '1712592355' 'default'\\\n");
        printf("                    'default' 'default'\n");
        printf("      * Important Notes *\n");
	    printf("      - Only effective for umounted process with uid >= 10000\n");
        return 0;
    }
    if (strcmp(cmd, "add_sus_kstat") == 0) {
        printf("    add_sus_kstat </path/of/file_or_directory>\n");
        printf("      |--> Add the desired path BEFORE it gets bind mounted or overlayed, this is used for storing original stat info in kernel memory\n");
        printf("      |--> This command must be completed with <update_sus_kstat> later after the added path is bind mounted or overlayed\n");
        printf("      * Important Notes *\n");
        printf("      - Only effective for umounted process with uid >= 10000\n");
        return 0;
    }
    if (strcmp(cmd, "update_sus_kstat") == 0) {
        printf("    update_sus_kstat </path/of/file_or_directory>\n");
        printf("      |--> Add the desired path you have added before via <add_sus_kstat> to complete the kstat spoofing procedure\n");
        printf("      |--> This updates the target ino, but size and blocks are remained the same as current stat\n");
        printf("      * Important Notes *\n");
        printf("      - Only effective for umounted process with uid >= 10000\n");
        return 0;
    }
    if (strcmp(cmd, "update_sus_kstat_full_clone") == 0) {
        printf("    update_sus_kstat_full_clone </path/of/file_or_directory>\n");
        printf("      |--> Add the desired path you have added before via <add_sus_kstat> to complete the kstat spoofing procedure\n");
        printf("      |--> This updates the target ino only, other stat members are remained the same as the original stat\n");
        printf("      * Important Notes *\n");
        printf("      - Only effective for umounted process with uid >= 10000\n");
        return 0;
    }
    if (strcmp(cmd, "add_try_umount") == 0) {
        printf("    add_try_umount </path/of/file_or_directory> <mode>\n");
        printf("      |--> Added path will be umounted from KSU for all UIDs that are NOT su allowed, and profile template configured with umount\n");
        printf("      |--> <mode>: 0 -> umount with no flags, 1 -> umount with MNT_DETACH\n");
        printf("      |--> NOTE: susfs umount takes precedence of ksu umount\n");
        return 0;
    }
    if (strcmp(cmd, "run_try_umount") == 0) {
        printf("        run_try_umount\n");
	    printf("         |--> Make all sus mounts to be private and umount them one by one in kernel for the mount namespace of current process\n");
        return 0;
    }
    if (strcmp(cmd, "set_uname") == 0) {
        printf("    set_uname <release> <version>\n");
        printf("      |--> Spoof uname for all processes, set string to 'default' to imply the function to use original string\n");
        printf("      |--> NOTE: only 'release' and <version> are spoofed as others are no longer needed\n");
        printf("     Example: %s set_uname '4.9.337-g3291538446b7' '#1 SMP PREEMPT Mon Oct 6 16:50:48 UTC 2025'\n", TAG);
        return 0;
    }
    if (strcmp(cmd, "enable_log") == 0) {
        printf("    enable_log <0|1>\n");
	    printf("      |--> 0: disable susfs log in kernel, 1: enable susfs log in kernel\n");
        return 0;
    }
    if (strcmp(cmd, "set_bootconfig") == 0) {
        printf("    set_bootconfig </path/to/file>\n");
        printf("      |--> Spoof the output of /proc/bootconfig from a text file\n");
        return 0;
    }
    if (strcmp(cmd, "set_cmdline_or_bootconfig") == 0) {
        printf("    set_cmdline_or_bootconfig </path/to/fake_cmdline_file/or/fake_bootconfig_file>\n");
	    printf("      |--> Spoof the output of /proc/cmdline (non-gki) or /proc/bootconfig (gki) from a text file\n");
        return 0;
    }
    if (strcmp(cmd, "add_open_redirect") == 0) {
        printf("    add_open_redirect </target/path> </redirected/path>\n");
        printf("      |--> Redirect the target path to be opened with user defined path\n");
        printf("      * Important Notes *\n");
        printf("      - Only effective for current process with uid <= 2000 or uid <= 11000 (for modified susfs kernels)\n");
        return 0;
    }
    if (strcmp(cmd, "add_sus_map") == 0) {
        printf("    add_sus_map </path/to/actual/library>\n");
        printf("      |--> added real file path which gets mmapped will be hidden from /proc/self/[maps|smaps|smaps_rollup|map_files|mem|pagemap]\n");
        printf("      |--> e.g., add_sus_map '/data/adb/modules/my_module/zygisk/arm64-v8a.so'\n");
        printf("      * Important Notes *\n");
        printf("      - It does NOT support hiding for anon memory.\n");
        printf("      - It does NOT hide any inline hooks or plt hooks cause by the injected library itself\n");
        printf("      - It may not be able to evade detections by apps that implement a good injection detection\n");
        printf("      - Only effective for umounted process with uid >= 10000\n");
        return 0;
    }
    if (strcmp(cmd, "enable_avc_log_spoofing") == 0) {
        printf("    enable_avc_log_spoofing <0|1>\n");
        printf("      |--> 0: Disable spoofing the sus 'su' tcontext shown in avc log in kernel\n");
        printf("      |--> 1: Enable spoofing the sus tcontext 'su' with 'kernel' shown in avc log in kernel\n");
        printf("      * Important Note *\n");
        printf("      - It is set to '0' by default in kernel\n");
        printf("      - Enable this will sometimes make developers hard to identify the cause when they are debugging with some permission or selinux issue, so users are advised to disable this when doing so.\n");
        return 0;
    }
    if (strcmp(cmd, "show") == 0) {
        printf("    show <version|enabled_features|variant>\n");
        printf("      |--> version: show the current susfs version implemented in kernel\n");
        printf("      |--> enabled_features: show the current implemented susfs features in kernel\n");
        printf("      |--> variant: show the current variant: GKI or NON-GKI\n");
        return 0;
    }
    if (strcmp(cmd, "sus_su") == 0) {
        printf("        sus_su <0|1|2|show_working_mode>\n");
        printf("         |--> NOTE-1:\n");
        printf("              - For mode 1: (deprecated) It disables kprobe hooks made by ksu, and instead,\n");
        printf("                a sus_su character device driver with random name will be created, and user\n");
        printf("                need to use a tool named 'sus_su' together with a path file in same current directory\n");
        printf("                named '" SUS_SU_CONF_FILE_PATH "' to get a root shell from the sus_su driver.'\n");
        printf("                ** sus_su userspace tool and an overlay mount is required **'\n");
        printf("              - For mode 2: It disables kprobe hooks made by ksu, and instead,\n");
        printf("                the non-kprobe inline hooks will be enbaled, just the same implementation for non-gki kernel without kprobe supported)\n");
        printf("                ** Needs no extra userspace tools and mounts **\n");
        printf("         |--> NOTE-2:\n");
        printf("                Please see the service.sh template from ksu_module_susfs for the usage\n");
        printf("         |--> 0: enable core ksu kprobe hooks and disable sus_su driver\n");
        printf("         |--> 1: (deprecated), disable the core ksu kprobe hooks and enable sus_su fifo driver\n");
        printf("         |--> 2: disable the core ksu kprobe hooks and enable sus_su just with non-kprobe hooks\n");
        printf("         |--> show_working_mode: show the current sus_su working mode, [0,1,2]\n");
        return 0;
    }

    /* Add more detailed help for other commands as needed */
    printf("[-] No additional help available for command '%s'\n", cmd);
    return 1;
}

/***************************
 ** Command implementations **
 ***************************/

/* ------------------------------------------------------------------ */
/* add_sus_path / add_sus_path_loop                                   */
/* ------------------------------------------------------------------ */
static int cmd_add_sus_path(const char *path, bool loop) {
    struct stat sb;
    if (get_file_stat(path, &sb)) {
        printf("[-] Failed to stat '%s'\n", path);
        return 1;
    }
    unsigned long cmd = loop ? CMD_SUSFS_ADD_SUS_PATH_LOOP : CMD_SUSFS_ADD_SUS_PATH;
    int ret;

    if (g_abi == ABI_v2000) {
        struct sus_path_v2000 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.target_ino = sb.st_ino;
        info.i_uid      = sb.st_uid;
        info.err        = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(cmd, &info);
        prt_not_supported(cmd, info.err);
        ret = info.err;
    } else if (HAVE(154)) {
        struct sus_path_v154 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.target_ino = sb.st_ino;
        info.i_uid      = sb.st_uid;
        ret = prctl_cmd(cmd, &info);
        prt_not_supported(cmd, ret);
    } else {
        struct sus_path_v1 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.target_ino = sb.st_ino;
        ret = prctl_cmd(cmd, &info);
        prt_not_supported(cmd, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* set_android_data_root_path / set_sdcard_root_path (v1.5.8+)        */
/* ------------------------------------------------------------------ */
static int cmd_set_external_dir(const char *path, unsigned long cmd) {
    int ret;
    if (g_abi == ABI_v2000) {
        struct external_dir_v2000 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.cmd = (int)cmd;
        info.err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(cmd, &info);
        prt_not_supported(cmd, info.err);
        ret = info.err;
    } else {
        /* prctl era: pass path as a plain pointer in arg3 */
        ret = prctl_cmd_scalar(cmd, (unsigned long)(uintptr_t)path);
        prt_not_supported(cmd, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* add_sus_mount                                                        */
/* ------------------------------------------------------------------ */
static int cmd_add_sus_mount(const char *path) {
    struct stat sb;
    if (get_file_stat(path, &sb)) {
        printf("[-] Failed to stat '%s'\n", path);
        return 1;
    }
    int ret;
    if (g_abi == ABI_v2000) {
        struct sus_mount_v2000 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.target_dev = sb.st_dev;
        info.err        = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ADD_SUS_MOUNT, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_MOUNT, info.err);
        ret = info.err;
    } else {
        struct sus_mount_v1 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.target_dev = sb.st_dev;
        ret = prctl_cmd(CMD_SUSFS_ADD_SUS_MOUNT, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_MOUNT, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* hide_sus_mnts  (all_procs pre-v2 / non_su_procs in v2)             */
/* ------------------------------------------------------------------ */
static int cmd_hide_sus_mnts(int enabled) {
    int ret;
    if (g_abi == ABI_v2000) {
        struct hide_sus_mnts_v2000 info = {0};
        info.enabled = (bool)enabled;
        info.err     = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_HIDE_SUS_MNTS, &info);
        prt_not_supported(CMD_SUSFS_HIDE_SUS_MNTS, info.err);
        ret = info.err;
    } else {
        ret = prctl_cmd_scalar(CMD_SUSFS_HIDE_SUS_MNTS, (unsigned long)enabled);
        prt_not_supported(CMD_SUSFS_HIDE_SUS_MNTS, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* umount_for_zygote_iso_service (v1.5.10+)                           */
/* ------------------------------------------------------------------ */
static int cmd_umount_zygote_iso(int enabled) {
    int ret;
    if (g_abi == ABI_v2000) {
        struct umount_zygote_v2000 info = {0};
        info.enabled = (bool)enabled;
        info.err     = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE, &info);
        prt_not_supported(CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE, info.err);
        ret = info.err;
    } else {
        ret = prctl_cmd_scalar(CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE, (unsigned long)enabled);
        prt_not_supported(CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* kstat helpers                                                        */
/* ------------------------------------------------------------------ */

/* Parse argv[4..14] into stat fields; "default" keeps the sb value. */
static int parse_kstat_argv(char **argv, struct stat *sb) {
    char *ep;
#define MAYBE_UL(idx, field) \
    if (strcmp(argv[idx], "default")) { \
        unsigned long _v = strtoul(argv[idx], &ep, 10); \
        if (*ep) return 1; \
        sb->field = _v; \
    }
#define MAYBE_SL(idx, field) \
    if (strcmp(argv[idx], "default")) { \
        long _v = strtol(argv[idx], &ep, 10); \
        if (*ep) return 1; \
        sb->field = _v; \
    }
    MAYBE_UL(4,  st_dev)
    MAYBE_UL(5,  st_nlink)
    MAYBE_UL(6,  st_size)
    MAYBE_SL(7,  st_atime)
    MAYBE_UL(8,  st_atimensec)
    MAYBE_SL(9,  st_mtime)
    MAYBE_UL(10, st_mtimensec)
    MAYBE_SL(11, st_ctime)
    MAYBE_UL(12, st_ctimensec)
    MAYBE_UL(13, st_blocks)
    MAYBE_UL(14, st_blksize)
#undef MAYBE_UL
#undef MAYBE_SL
    return 0;
}

/* ------------------------------------------------------------------ */
/* add_sus_kstat_statically                                            */
/* ------------------------------------------------------------------ */
static int cmd_add_sus_kstat_statically(char **argv) {
    struct stat sb;
    if (get_file_stat(argv[2], &sb)) {
        printf("[-] Failed to stat '%s'\n", argv[2]);
        return 1;
    }
    unsigned long orig_ino = sb.st_ino;

    if (strcmp(argv[3], "default")) {
        char *ep;
        sb.st_ino = strtoul(argv[3], &ep, 10);
        if (*ep) { print_help(); return 1; }
    }
    if (parse_kstat_argv(argv, &sb)) { print_help(); return 1; }

    int ret;
    if (g_abi == ABI_v2000) {
        struct sus_kstat_v2000 info = {0};
        strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME - 1);
        info.is_statically = true;
        info.target_ino    = orig_ino;
        copy_stat_to_kstat_v2000(&info, &sb);
        info.err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, info.err);
        ret = info.err;
    } else {
        struct sus_kstat_v1 info = {0};
        strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME - 1);
        info.is_statically = true;
        info.target_ino    = orig_ino;
        copy_stat_to_kstat_v1(&info, &sb);
        ret = prctl_cmd(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* add_sus_kstat                                                        */
/* ------------------------------------------------------------------ */
static int cmd_add_sus_kstat(const char *path) {
    struct stat sb;
    if (get_file_stat(path, &sb)) { printf("[-] Failed to stat '%s'\n", path); return 1; }
    int ret;
    if (g_abi == ABI_v2000) {
        struct sus_kstat_v2000 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.is_statically = false;
        info.target_ino    = sb.st_ino;
        copy_stat_to_kstat_v2000(&info, &sb);
        info.err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ADD_SUS_KSTAT, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_KSTAT, info.err);
        ret = info.err;
    } else {
        struct sus_kstat_v1 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.is_statically = false;
        info.target_ino    = sb.st_ino;
        copy_stat_to_kstat_v1(&info, &sb);
        ret = prctl_cmd(CMD_SUSFS_ADD_SUS_KSTAT, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_KSTAT, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* update_sus_kstat / update_sus_kstat_full_clone                     */
/* ------------------------------------------------------------------ */
static int cmd_update_sus_kstat(const char *path, bool full_clone) {
    struct stat sb;
    if (get_file_stat(path, &sb)) { printf("[-] Failed to stat '%s'\n", path); return 1; }
    int ret;
    if (g_abi == ABI_v2000) {
        struct sus_kstat_v2000 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.is_statically = false;
        info.target_ino    = sb.st_ino;
        if (!full_clone) {
            info.spoofed_size   = sb.st_size;
            info.spoofed_blocks = sb.st_blocks;
        }
        info.err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_UPDATE_SUS_KSTAT, &info);
        prt_not_supported(CMD_SUSFS_UPDATE_SUS_KSTAT, info.err);
        ret = info.err;
    } else {
        struct sus_kstat_v1 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.is_statically = false;
        info.target_ino    = sb.st_ino;
        if (!full_clone) {
            info.spoofed_size   = sb.st_size;
            info.spoofed_blocks = sb.st_blocks;
        }
        ret = prctl_cmd(CMD_SUSFS_UPDATE_SUS_KSTAT, &info);
        prt_not_supported(CMD_SUSFS_UPDATE_SUS_KSTAT, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* add_try_umount                                                       */
/* ------------------------------------------------------------------ */
static int cmd_add_try_umount(const char *path, int mnt_mode) {
    char abs[PATH_MAX];
    if (!realpath(path, abs)) { perror("realpath"); return 1; }

    /* Blocklist: paths managed by ksu itself -- differs between ABIs */
    const char *blocked_v2000[] = { "/odm", "/system", "/vendor", "/product",
                                   "/system_ext", "/data/adb/modules", NULL };
    const char *blocked_v1[]   = { "/system", "/vendor", "/product",
                                   "/data/adb/modules", "/debug_ramdisk", "/sbin", NULL };
    const char **bl = (g_abi == ABI_v2000) ? blocked_v2000 : blocked_v1;
    for (int i = 0; bl[i]; i++) {
        if (!strcmp(abs, bl[i])) {
            printf("[-] %s cannot be added to try_umount (managed by ksu)\n", abs);
            return -EINVAL;
        }
    }

    int ret;
    if (g_abi == ABI_v2000) {
        struct try_umount_v2000 info = {0};
        strncpy(info.target_pathname, abs, SUSFS_MAX_LEN_PATHNAME - 1);
        info.mnt_mode = mnt_mode;
        info.err      = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ADD_TRY_UMOUNT, &info);
        prt_not_supported(CMD_SUSFS_ADD_TRY_UMOUNT, info.err);
        ret = info.err;
    } else {
        struct try_umount_v1 info = {0};
        strncpy(info.target_pathname, abs, SUSFS_MAX_LEN_PATHNAME - 1);
        info.mnt_mode = mnt_mode;
        ret = prctl_cmd(CMD_SUSFS_ADD_TRY_UMOUNT, &info);
        prt_not_supported(CMD_SUSFS_ADD_TRY_UMOUNT, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* set_uname                                                            */
/* ------------------------------------------------------------------ */
static int cmd_set_uname(const char *release, const char *version) {
    int ret;
    if (g_abi == ABI_v2000) {
        struct uname_v2000 info = {0};
        strncpy(info.release, release, __NEW_UTS_LEN);
        strncpy(info.version, version, __NEW_UTS_LEN);
        info.err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_SET_UNAME, &info);
        prt_not_supported(CMD_SUSFS_SET_UNAME, info.err);
        ret = info.err;
    } else {
        struct uname_v1 info = {0};
        strncpy(info.release, release, __NEW_UTS_LEN);
        strncpy(info.version, version, __NEW_UTS_LEN);
        ret = prctl_cmd(CMD_SUSFS_SET_UNAME, &info);
        prt_not_supported(CMD_SUSFS_SET_UNAME, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* enable_log                                                           */
/* ------------------------------------------------------------------ */
static int cmd_enable_log(int enabled) {
    int ret;
    if (g_abi == ABI_v2000) {
        struct log_v2000 info = {0};
        info.enabled = (bool)enabled;
        info.err     = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ENABLE_LOG, &info);
        prt_not_supported(CMD_SUSFS_ENABLE_LOG, info.err);
        ret = info.err;
    } else {
        ret = prctl_cmd_scalar(CMD_SUSFS_ENABLE_LOG, (unsigned long)enabled);
        prt_not_supported(CMD_SUSFS_ENABLE_LOG, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* set_bootconfig / set_cmdline_or_bootconfig                          */
/* ------------------------------------------------------------------ */
static int cmd_set_cmdline_or_bootconfig(const char *filepath) {
    int ret;
    if (g_abi == ABI_v2000) {
        struct spoof_cmdline_v2000 *info = calloc(1, sizeof(*info));
        if (!info) { perror("calloc"); return -ENOMEM; }
        char abs[PATH_MAX];
        if (!realpath(filepath, abs)) { perror("realpath"); free(info); return 1; }
        FILE *f = fopen(abs, "rb");
        if (!f) { perror("fopen"); free(info); return 1; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        if (sz >= (long)sizeof(info->fake_cmdline_or_bootconfig)) {
            printf("[-] File too large (max %zu bytes)\n",
                   sizeof(info->fake_cmdline_or_bootconfig) - 1);
            fclose(f); free(info); return -EINVAL;
        }
        if ((long)fread(info->fake_cmdline_or_bootconfig, 1, (size_t)sz, f) != sz) {
            perror("fread"); fclose(f); free(info); return 1;
        }
        fclose(f);
        info->err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG, info);
        prt_not_supported(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG, info->err);
        ret = info->err;
        free(info);
    } else {
        char *buf;
        if (read_file_to_buf(filepath, &buf, NULL)) return 1;
        ret = prctl_cmd(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG, buf);
        free(buf);
        prt_not_supported(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* add_open_redirect                                                    */
/* ------------------------------------------------------------------ */
static int cmd_add_open_redirect(const char *target, const char *redirect) {
    char abs_t[PATH_MAX], abs_r[PATH_MAX];
    if (!realpath(target,   abs_t)) { perror("realpath(target)");   return 1; }
    if (!realpath(redirect, abs_r)) { perror("realpath(redirect)"); return 1; }
    struct stat sb;
    if (get_file_stat(abs_t, &sb)) { printf("[-] Failed to stat '%s'\n", abs_t); return 1; }
    int ret;
    if (g_abi == ABI_v2000) {
        struct open_redirect_v2000 info = {0};
        strncpy(info.target_pathname,     abs_t, SUSFS_MAX_LEN_PATHNAME - 1);
        strncpy(info.redirected_pathname, abs_r, SUSFS_MAX_LEN_PATHNAME - 1);
        info.target_ino = sb.st_ino;
        info.err        = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ADD_OPEN_REDIRECT, &info);
        prt_not_supported(CMD_SUSFS_ADD_OPEN_REDIRECT, info.err);
        ret = info.err;
    } else {
        struct open_redirect_v1 info = {0};
        strncpy(info.target_pathname,     abs_t, SUSFS_MAX_LEN_PATHNAME - 1);
        strncpy(info.redirected_pathname, abs_r, SUSFS_MAX_LEN_PATHNAME - 1);
        info.target_ino = sb.st_ino;
        ret = prctl_cmd(CMD_SUSFS_ADD_OPEN_REDIRECT, &info);
        prt_not_supported(CMD_SUSFS_ADD_OPEN_REDIRECT, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* add_sus_map (v1.5.12+)                                              */
/* ------------------------------------------------------------------ */
static int cmd_add_sus_map(const char *path) {
    int ret;
    if (g_abi == ABI_v2000) {
        struct sus_map_v2000 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ADD_SUS_MAP, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_MAP, info.err);
        ret = info.err;
    } else {
        struct sus_map_v1 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        ret = prctl_cmd(CMD_SUSFS_ADD_SUS_MAP, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_MAP, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* enable_avc_log_spoofing (v1.5.10+)                                  */
/* ------------------------------------------------------------------ */
static int cmd_enable_avc_log_spoofing(int enabled) {
    int ret;
    if (g_abi == ABI_v2000) {
        struct avc_log_v2000 info = {0};
        info.enabled = (bool)enabled;
        info.err     = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING, &info);
        prt_not_supported(CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING, info.err);
        ret = info.err;
    } else {
        ret = prctl_cmd_scalar(CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING, (unsigned long)enabled);
        prt_not_supported(CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING, ret);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* show version / enabled_features / variant (v1.5.3+)                */
/* ------------------------------------------------------------------ */
static int cmd_show(const char *what) {
    if (!strcmp(what, "version")) {
        if (g_abi == ABI_v2000) {
            struct version_v2000 info = {0};
            info.err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(CMD_SUSFS_SHOW_VERSION, &info);
            prt_not_supported(CMD_SUSFS_SHOW_VERSION, info.err);
            if (!info.err) printf("%s\n", info.susfs_version);
            return info.err;
        } else {
            char buf[16] = {0};
            int r = prctl_cmd(CMD_SUSFS_SHOW_VERSION, buf);
            prt_not_supported(CMD_SUSFS_SHOW_VERSION, r);
            if (!r) printf("%s\n", buf);
            return r;
        }

    } else if (!strcmp(what, "enabled_features")) {
        if (g_abi == ABI_v2000) {
            struct enabled_features_v2000 *info = calloc(1, sizeof(*info));
            if (!info) { perror("calloc"); return -ENOMEM; }
            info->err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(CMD_SUSFS_SHOW_ENABLED_FEATURES, info);
            prt_not_supported(CMD_SUSFS_SHOW_ENABLED_FEATURES, info->err);
            int r = info->err;
            if (!r) printf("%s", info->enabled_features);
            free(info);
            return r;
        } else if (HAVE(159)) {
            /* v1.5.9+: kernel writes a human-readable string directly into the buffer */
            size_t bufsz = (size_t)getpagesize() * 2;
            char *buf = malloc(bufsz);
            if (!buf) { perror("malloc"); return -ENOMEM; }
            int r = prctl_cmd4(CMD_SUSFS_SHOW_ENABLED_FEATURES, buf, (unsigned long)bufsz);
            prt_not_supported(CMD_SUSFS_SHOW_ENABLED_FEATURES, r);
            if (!r) printf("%s", buf);
            free(buf);
            return r;
        } else {
            /* v1.5.3-v1.5.8: kernel returns an integer bitmask */
            unsigned long mask = 0;
            int r = prctl_cmd(CMD_SUSFS_SHOW_ENABLED_FEATURES, &mask);
            prt_not_supported(CMD_SUSFS_SHOW_ENABLED_FEATURES, r);
            if (r) return r;

            /*
                * The bit positions for features are stable across these versions, but the features themselves may differ.
                 * So we prepare the names for all versions and print according to the version.
             */
            const char *names_153[] = {
                "CONFIG_KSU_SUSFS_SUS_PATH",
                "CONFIG_KSU_SUSFS_SUS_MOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT",
                "CONFIG_KSU_SUSFS_SUS_KSTAT",
                "CONFIG_KSU_SUSFS_SUS_OVERLAYFS",
                "CONFIG_KSU_SUSFS_TRY_UMOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT",
                "CONFIG_KSU_SUSFS_SPOOF_UNAME",
                "CONFIG_KSU_SUSFS_ENABLE_LOG",
                "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS",
                "CONFIG_KSU_SUSFS_SPOOF_BOOTCONFIG",
                "CONFIG_KSU_SUSFS_OPEN_REDIRECT",
                "CONFIG_KSU_SUSFS_SUS_SU",
                NULL
            };
            const char *names_154[] = {
                "CONFIG_KSU_SUSFS_SUS_PATH",
                "CONFIG_KSU_SUSFS_SUS_MOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT",
                "CONFIG_KSU_SUSFS_SUS_KSTAT",
                "CONFIG_KSU_SUSFS_SUS_OVERLAYFS",
                "CONFIG_KSU_SUSFS_TRY_UMOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT",
                "CONFIG_KSU_SUSFS_SPOOF_UNAME",
                "CONFIG_KSU_SUSFS_ENABLE_LOG",
                "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS",
                "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG",
                "CONFIG_KSU_SUSFS_OPEN_REDIRECT",
                "CONFIG_KSU_SUSFS_SUS_SU",
                "CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT",
                NULL
            };
            const char *names_158[] = {
                "CONFIG_KSU_SUSFS_SUS_PATH",
                "CONFIG_KSU_SUSFS_SUS_MOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT",
                "CONFIG_KSU_SUSFS_SUS_KSTAT",
                "CONFIG_KSU_SUSFS_TRY_UMOUNT",
                "CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT",
                "CONFIG_KSU_SUSFS_SPOOF_UNAME",
                "CONFIG_KSU_SUSFS_ENABLE_LOG",
                "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS",
                "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG",
                "CONFIG_KSU_SUSFS_OPEN_REDIRECT",
                "CONFIG_KSU_SUSFS_SUS_SU",
                "CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT",
                NULL
            };
            const char **names = (g_version == 153) ? names_153 : (g_version == 154) ? names_154 : names_158;
            for (int bit = 0; names[bit]; bit++)
                if (mask & (1UL << bit))
                    printf("%s\n", names[bit]);
            return 0;
        }

    } else if (!strcmp(what, "variant")) {
        if (g_abi == ABI_v2000) {
            struct variant_v2000 info = {0};
            info.err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(CMD_SUSFS_SHOW_VARIANT, &info);
            prt_not_supported(CMD_SUSFS_SHOW_VARIANT, info.err);
            if (!info.err) printf("%s\n", info.susfs_variant);
            return info.err;
        } else {
            char buf[16] = {0};
            int r = prctl_cmd(CMD_SUSFS_SHOW_VARIANT, buf);
            prt_not_supported(CMD_SUSFS_SHOW_VARIANT, r);
            if (!r) printf("%s\n", buf);
            return r;
        }
    }

    print_help();
    return 1;
}

/* ------------------------------------------------------------------ */
/* sus_su (prctl ABI only)                                             */
/* ------------------------------------------------------------------ */

static int enable_sus_su_prctl(int last_mode, int target_mode) {
    struct sus_su_v153 info = {0};
    info.mode  = target_mode;
    int error = prctl_cmd(CMD_SUSFS_SUS_SU, &info);
    prt_not_supported(CMD_SUSFS_SUS_SU, error);
    if (error) {
        if (error == 1) printf("[-] sus_su is already in mode %d\n", target_mode);
        else if (error == 2) printf("[-] please set mode %d first\n", SUS_SU_DISABLED);
        return error;
    }
    printf("[+] sus_su mode %d is enabled\n", target_mode);
    return 0;
}

static int cmd_sus_su(const char *arg) {
    if (g_version == 152) {
        /* v1.5.2: mknod-based legacy flow */
        struct sus_su_v152 info = {0};
        info.maj_dev_num = -1;
        int error;

        if (!strcmp(arg, "1")) {
            info.mode = SUS_SU_WITH_OVERLAY;
            error = prctl_cmd(CMD_SUSFS_SUS_SU, &info);
            prt_not_supported(CMD_SUSFS_SUS_SU, error);
            if (error) return error;
            dev_t dev = makedev(info.maj_dev_num, 0);
            if (mknod(info.drv_path, S_IFCHR | 0666, dev) < 0) {
                printf("[-] mknod '%s' failed\n", info.drv_path);
                return 1;
            }
            FILE *fp = fopen(SUS_SU_CONF_FILE_PATH, "w");
            if (!fp) { printf("[-] cannot write conf\n"); return 1; }
            fputs(info.drv_path, fp);
            fclose(fp);
            if (system("export DRV_PATH=`cat " SUS_SU_CONF_FILE_PATH
                       "`; chmod 666 ${DRV_PATH} && chcon u:object_r:null_device:s0 ${DRV_PATH}")) {
                printf("[-] chmod failed for '%s'\n", info.drv_path);
                return 1;
            }
        } else if (!strcmp(arg, "0")) {
            info.mode = SUS_SU_DISABLED;
            error = prctl_cmd(CMD_SUSFS_SUS_SU, &info);
            prt_not_supported(CMD_SUSFS_SUS_SU, error);
            if (!error)
                system("export DRV_PATH=`cat " SUS_SU_CONF_FILE_PATH "`; rm -f ${DRV_PATH}");
        } else if (!strcmp(arg, "2")) {
            info.mode = SUS_SU_WITH_HOOKS;
            error = prctl_cmd(CMD_SUSFS_SUS_SU, &info);
            prt_not_supported(CMD_SUSFS_SUS_SU, error);
        } else {
            print_help(); return 1;
        }
        return error;
    }

    /* v1.5.3+: simplified mode */
    int last_mode = 0;
    int r = prctl_cmd(CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE, &last_mode);
    prt_not_supported(CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE, r);
    if (r) return r;

    if (!strcmp(arg, "show_working_mode")) {
        printf("%d\n", last_mode);
        return 0;
    }
    if (!strcmp(arg, "1")) {
        printf("[-] sus_su mode 1 is deprecated\n");
        return 1;
    }

    char *ep;
    int target = (int)strtol(arg, &ep, 10);
    if (*ep) { print_help(); return 1; }

    if (target == SUS_SU_WITH_HOOKS) {
        bool ready = false;
        r = prctl_cmd(CMD_SUSFS_IS_SUS_SU_READY, &ready);
        prt_not_supported(CMD_SUSFS_IS_SUS_SU_READY, r);
        if (r) return r;
        if (!ready) {
            printf("[-] sus_su mode %d must be run during or after service stage\n",
                   SUS_SU_WITH_HOOKS);
            return 1;
        }
        if (last_mode == SUS_SU_WITH_HOOKS) {
            printf("[-] sus_su is already in mode %d\n", last_mode);
            return 1;
        }
        if (last_mode != SUS_SU_DISABLED) {
            r = enable_sus_su_prctl(last_mode, SUS_SU_DISABLED);
            if (r) return r;
        }
        return enable_sus_su_prctl(last_mode, SUS_SU_WITH_HOOKS);
    }

    if (target == SUS_SU_DISABLED) {
        if (last_mode == SUS_SU_DISABLED) {
            printf("[-] sus_su is already in mode %d\n", last_mode);
            return 1;
        }
        return enable_sus_su_prctl(last_mode, SUS_SU_DISABLED);
    }

    print_help();
    return 1;
}

/*******************
 ** Main Function **
 *******************/
int main(int argc, char *argv[]) {
    pre_check();
    detect_susfs_version();

    if (argc < 2) {
        print_help();
        return 0;
    }

    const char *cmd = argv[1];

    if (!strcmp(cmd, "--help") && argc == 3) {
        print_more_help(argv[2]);
        return 0;
    }

    if (!strcmp(cmd, "add_sus_path") && argc == 3)
        return cmd_add_sus_path(argv[2], false);

    if (!strcmp(cmd, "add_sus_path_loop") && argc == 3) {
        return cmd_add_sus_path(argv[2], true);
    }

    if (!strcmp(cmd, "set_android_data_root_path") && argc == 3) {
        if (!HAVE(158)) { printf("[-] Requires susfs v1.5.8+\n"); return 1; }
        return cmd_set_external_dir(argv[2], CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH);
    }

    if (!strcmp(cmd, "set_sdcard_root_path") && argc == 3) {
        if (!HAVE(158)) { printf("[-] Requires susfs v1.5.8+\n"); return 1; }
        return cmd_set_external_dir(argv[2], CMD_SUSFS_SET_SDCARD_ROOT_PATH);
    }

    if (!strcmp(cmd, "add_sus_mount") && argc == 3)
        return cmd_add_sus_mount(argv[2]);

    if (!strcmp(cmd, "hide_sus_mnts_for_all_procs") && argc == 3) {
        if (g_abi == ABI_v2000) {
            printf("[-] v2.0.0+: use 'hide_sus_mnts_for_non_su_procs' instead\n");
            return 1;
        }
        if (!HAVE(158)) { printf("[-] Requires susfs v1.5.8+\n"); return 1; }
        if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) { print_help(); return 1; }
        return cmd_hide_sus_mnts(atoi(argv[2]));
    }

    if (!strcmp(cmd, "hide_sus_mnts_for_non_su_procs") && argc == 3) {
        if (g_abi != ABI_v2000) {
            printf("[-] v1.5.x: use 'hide_sus_mnts_for_all_procs' instead\n");
            return 1;
        }
        if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) { print_help(); return 1; }
        return cmd_hide_sus_mnts(atoi(argv[2]));
    }

    if (!strcmp(cmd, "umount_for_zygote_iso_service") && argc == 3) {
        if (!HAVE(1510)) { printf("[-] Requires susfs v1.5.10+\n"); return 1; }
        if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) { print_help(); return 1; }
        return cmd_umount_zygote_iso(atoi(argv[2]));
    }

    if (!strcmp(cmd, "add_sus_kstat_statically") && argc == 15)
        return cmd_add_sus_kstat_statically(argv);

    if (!strcmp(cmd, "add_sus_kstat") && argc == 3)
        return cmd_add_sus_kstat(argv[2]);

    if (!strcmp(cmd, "update_sus_kstat") && argc == 3)
        return cmd_update_sus_kstat(argv[2], false);

    if (!strcmp(cmd, "update_sus_kstat_full_clone") && argc == 3)
        return cmd_update_sus_kstat(argv[2], true);

    if (!strcmp(cmd, "add_try_umount") && argc == 4) {
        if (strcmp(argv[3], "0") && strcmp(argv[3], "1")) { print_help(); return 1; }
        return cmd_add_try_umount(argv[2], atoi(argv[3]));
    }

    if (!strcmp(cmd, "run_try_umount") && argc == 2) {
        if (HAVE(1512)) { printf("[-] run_try_umount is not available in susfs v1.5.12+\n"); return 1; }
        int r = prctl_cmd_scalar(CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS, 0);
        prt_not_supported(CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS, r);
        return r;
    }

    if (!strcmp(cmd, "set_uname") && argc == 4)
        return cmd_set_uname(argv[2], argv[3]);

    if (!strcmp(cmd, "enable_log") && argc == 3) {
        if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) { print_help(); return 1; }
        return cmd_enable_log(atoi(argv[2]));
    }

    /* set_bootconfig: v1.5.2/v1.5.3 name, same opcode as set_cmdline_or_bootconfig */
    if (!strcmp(cmd, "set_bootconfig") && argc == 3) {
        if (HAVE(154)) {
            printf("[-] v1.5.4+: use 'set_cmdline_or_bootconfig' instead\n");
            return 1;
        }
        return cmd_set_cmdline_or_bootconfig(argv[2]);
    }

    if (!strcmp(cmd, "set_cmdline_or_bootconfig") && argc == 3) {
        if (!HAVE(154) && g_abi != ABI_v2000) {
            printf("[-] v1.5.2/v1.5.3: use 'set_bootconfig' instead\n");
            return 1;
        }
        return cmd_set_cmdline_or_bootconfig(argv[2]);
    }

    if (!strcmp(cmd, "add_open_redirect") && argc == 4)
        return cmd_add_open_redirect(argv[2], argv[3]);

    if (!strcmp(cmd, "add_sus_map") && argc == 3) {
        if (!HAVE(1512)) { printf("[-] Requires susfs v1.5.12+\n"); return 1; }
        return cmd_add_sus_map(argv[2]);
    }

    if (!strcmp(cmd, "enable_avc_log_spoofing") && argc == 3) {
        if (!HAVE(1510)) { printf("[-] Requires susfs v1.5.10+\n"); return 1; }
        if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) { print_help(); return 1; }
        return cmd_enable_avc_log_spoofing(atoi(argv[2]));
    }

    if (!strcmp(cmd, "show") && argc == 3) {
        if (!HAVE(153)) { printf("[-] Requires susfs v1.5.3+\n"); return 1; }
        return cmd_show(argv[2]);
    }

    if (!strcmp(cmd, "sus_su") && argc == 3) {
        if (g_abi == ABI_v2000) {
            printf("[-] sus_su is deprecated in v2.0.0+\n");
            return 1;
        }
        return cmd_sus_su(argv[2]);
    }

    print_help();
    free(g_version_string);
    return 254;
}
