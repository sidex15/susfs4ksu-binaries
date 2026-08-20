/*
 * commands.c - implementations of every ksu_susfs subcommand.
 *
 * Each cmd_* function selects the correct kernel ABI/struct layout at runtime
 * based on the globals populated by detect_susfs_version().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/limits.h>

#include "susfs.h"

/* ------------------------------------------------------------------ */
/* add_sus_path / add_sus_path_loop                                   */
/* ------------------------------------------------------------------ */
int cmd_add_sus_path(const char *path, bool loop) {
    unsigned long cmd = loop ? CMD_SUSFS_ADD_SUS_PATH_LOOP : CMD_SUSFS_ADD_SUS_PATH;
    /* Default 0 covers the v2.0.0 path where the new-layout probe fails while
     * the layout is still UNKNOWN and neither branch assigns ret. */
    int ret = 0;

    if (g_abi == ABI_v2000) {
        /* Try new struct layout first (or use cached result) */
        if ((g_v2000_sus_path_layout != V2000_SUS_PATH_LAYOUT_OLD) || HAVE(2100)) {
            struct sus_path_v2000_new info = {0};
            strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
            info.err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(cmd, &info);
            if (info.err == 0 || g_v2000_sus_path_layout == V2000_SUS_PATH_LAYOUT_NEW) {
                g_v2000_sus_path_layout = V2000_SUS_PATH_LAYOUT_NEW;
                clear_old_sus_path_layout_cache();
                prt_not_supported(cmd, info.err);
                return info.err;
            }
        } else { /* New layout failed and not yet cached — fall through to old layout */
            struct stat sb;
            if (get_file_stat(path, &sb)) {
                printf("[-] Failed to stat '%s'\n", path);
                return 1;
            }
            struct sus_path_v2000 info = {0};
            strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
            info.target_ino = sb.st_ino;
            info.i_uid      = sb.st_uid;
            info.err        = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(cmd, &info);
            if (info.err == 0) {
                g_v2000_sus_path_layout = V2000_SUS_PATH_LAYOUT_OLD;
                persist_old_sus_path_layout_cache();
            }
            prt_not_supported(cmd, info.err);
            ret = info.err;
        }
    } else {
        struct stat sb;
        if (get_file_stat(path, &sb)) {
            printf("[-] Failed to stat '%s'\n", path);
            return 1;
        }
        if (HAVE(154)) {
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
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* set_android_data_root_path / set_sdcard_root_path (v1.5.8-v2.0.0)        */
/* ------------------------------------------------------------------ */
int cmd_set_external_dir(const char *path, unsigned long cmd) {
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
int cmd_add_sus_mount(const char *path) {
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
int cmd_hide_sus_mnts(int enabled) {
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
int cmd_umount_zygote_iso(int enabled) {
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

/* Parse argv[4..14] into stat fields; "default" keeps the sb value.
 * For v2.1.0, set the corresponding spoof flags when a value is overridden.
 */
static int parse_kstat_argv(char **argv, struct stat *sb, int *flags) {
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
    if (strcmp(argv[4], "default")) {
        MAYBE_UL(4, st_dev)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_DEV;
    }
    if (strcmp(argv[5], "default")) {
        MAYBE_UL(5, st_nlink)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_NLINK;
    }
    if (strcmp(argv[6], "default")) {
        MAYBE_UL(6, st_size)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_SIZE;
    }
    if (strcmp(argv[7], "default")) {
        MAYBE_SL(7, st_atime)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_ATIME_TV_SEC;
    }
    if (strcmp(argv[8], "default")) {
        MAYBE_UL(8, st_atimensec)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_ATIME_TV_NSEC;
    }
    if (strcmp(argv[9], "default")) {
        MAYBE_SL(9, st_mtime)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_MTIME_TV_SEC;
    }
    if (strcmp(argv[10], "default")) {
        MAYBE_UL(10, st_mtimensec)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_MTIME_TV_NSEC;
    }
    if (strcmp(argv[11], "default")) {
        MAYBE_SL(11, st_ctime)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_CTIME_TV_SEC;
    }
    if (strcmp(argv[12], "default")) {
        MAYBE_UL(12, st_ctimensec)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_CTIME_TV_NSEC;
    }
    if (strcmp(argv[13], "default")) {
        MAYBE_UL(13, st_blocks)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_BLOCKS;
    }
    if (strcmp(argv[14], "default")) {
        MAYBE_UL(14, st_blksize)
        if (flags && HAVE(2100)) *flags |= KSTAT_SPOOF_BLKSIZE;
    }
#undef MAYBE_UL
#undef MAYBE_SL
    return 0;
}

/* ------------------------------------------------------------------ */
/* add_sus_kstat_statically                                            */
/* ------------------------------------------------------------------ */
int cmd_add_sus_kstat_statically(char **argv) {
    struct stat sb;
    if (get_file_stat(argv[2], &sb)) {
        printf("[-] Failed to stat '%s'\n", argv[2]);
        return 1;
    }
    unsigned long orig_ino = sb.st_ino;
    int flags = 0;

    if (strcmp(argv[3], "default")) {
        char *ep;
        sb.st_ino = strtoul(argv[3], &ep, 10);
        if (*ep) { print_help(); return 1; }
        if (HAVE(2100))
            flags |= KSTAT_SPOOF_INO;
    }
    if (parse_kstat_argv(argv, &sb, &flags)) { print_help(); return 1; }

    int ret;
    if (g_abi == ABI_v2000) {
        if (HAVE(2100)) {
            struct sus_kstat_v2100 info = {0};
            strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME - 1);
            info.is_statically = true;
            info.target_ino    = orig_ino;
            info.flags         = flags;
            copy_stat_to_kstat_v2100(&info, &sb);
            info.err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, &info);
            prt_not_supported(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, info.err);
            ret = info.err;
        } else {
            struct sus_kstat_v2000 info = {0};
            strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME - 1);
            info.is_statically = true;
            info.target_ino    = orig_ino;
            copy_stat_to_kstat_v2000(&info, &sb);
            info.err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, &info);
            prt_not_supported(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, info.err);
            ret = info.err;
        }
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
int cmd_add_sus_kstat(const char *path) {
    struct stat sb;
    if (get_file_stat(path, &sb)) { printf("[-] Failed to stat '%s'\n", path); return 1; }
    int ret;
    if (g_abi == ABI_v2000) {
        if (HAVE(2100)) {
            struct sus_kstat_v2100 info = {0};
            strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
            info.is_statically = false;
            info.target_ino    = sb.st_ino;
            info.flags         = KSTAT_AUTO_SPOOF;
            copy_stat_to_kstat_v2100(&info, &sb);
            info.err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(CMD_SUSFS_ADD_SUS_KSTAT, &info);
            prt_not_supported(CMD_SUSFS_ADD_SUS_KSTAT, info.err);
            ret = info.err;
        } else {
            struct sus_kstat_v2000 info = {0};
            strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
            info.is_statically = false;
            info.target_ino    = sb.st_ino;
            copy_stat_to_kstat_v2000(&info, &sb);
            info.err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(CMD_SUSFS_ADD_SUS_KSTAT, &info);
            prt_not_supported(CMD_SUSFS_ADD_SUS_KSTAT, info.err);
            ret = info.err;
        }
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
int cmd_update_sus_kstat(const char *path, bool full_clone) {
    struct stat sb;
    if (get_file_stat(path, &sb)) { printf("[-] Failed to stat '%s'\n", path); return 1; }
    int ret;
    if (g_abi == ABI_v2000) {
        if (HAVE(2100)) {
            struct sus_kstat_v2100 info = {0};
            strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
            info.is_statically = false;
            info.target_ino    = sb.st_ino;
            info.flags = full_clone ? KSTAT_AUTO_SPOOF_FULL_CLONE : KSTAT_AUTO_SPOOF;
            copy_stat_to_kstat_v2100(&info, &sb);
            info.err = ERR_v2000_CMD_NOT_SUPPORTED;
            v2000_cmd(CMD_SUSFS_UPDATE_SUS_KSTAT, &info);
            prt_not_supported(CMD_SUSFS_UPDATE_SUS_KSTAT, info.err);
            ret = info.err;
        } else {
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
        }
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
int cmd_add_try_umount(const char *path, int mnt_mode) {
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
int cmd_set_uname(const char *release, const char *version) {
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
int cmd_enable_log(int enabled) {
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
int cmd_set_cmdline_or_bootconfig(const char *filepath) {
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
int cmd_add_open_redirect(const char *target, const char *redirect) {
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

int cmd_add_open_redirect_2100(const char *target, const char *redirect, const char *uid) {
    char abs_t[PATH_MAX], abs_r[PATH_MAX];
    if (!realpath(target,   abs_t)) { perror("realpath(target)");   return 1; }
    if (!realpath(redirect, abs_r)) { perror("realpath(redirect)"); return 1; }
    struct stat sb;
    if (get_file_stat(abs_t, &sb)) { printf("[-] Failed to stat '%s'\n", abs_t); return 1; }
    int ret;

    struct open_redirect_v2100 info = {0};
    char *endptr;
    long uid_scheme;

    uid_scheme = strtol(uid, &endptr, 10);
    if (*endptr != '\0') {
        print_help();
        return -EINVAL;
    }

    if (uid_scheme < UID_NON_APP_PROC || uid_scheme > UID_UMOUNTED_PROC) {
        print_help();
        return -EINVAL;
    }

    info.uid_scheme = uid_scheme;
    strncpy(info.target_pathname, abs_t, SUSFS_MAX_LEN_PATHNAME - 1);
    strncpy(info.redirected_pathname, abs_r, SUSFS_MAX_LEN_PATHNAME - 1);
    info.err        = ERR_v2000_CMD_NOT_SUPPORTED;
    v2000_cmd(CMD_SUSFS_ADD_OPEN_REDIRECT, &info);
    prt_not_supported(CMD_SUSFS_ADD_OPEN_REDIRECT, info.err);
    ret = info.err;
    return ret;
}

/* ------------------------------------------------------------------ */
/* add_sus_map (v1.5.12+)                                              */
/* ------------------------------------------------------------------ */
int cmd_add_sus_map(const char *path) {
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
/* add_sus_memfd (exclusive feature)                                  */
/* ------------------------------------------------------------------ */

int cmd_add_sus_memfd(const char *path){
	int ret;
    if (g_abi == ABI_v2000) {
        struct sus_memfd_v2000 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        info.err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_ADD_SUS_MEMFD, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_MEMFD, info.err);
        ret = info.err;
    } else {
        struct sus_memfd_v1 info = {0};
        strncpy(info.target_pathname, path, SUSFS_MAX_LEN_PATHNAME - 1);
        ret = prctl_cmd(CMD_SUSFS_ADD_SUS_MEMFD, &info);
        prt_not_supported(CMD_SUSFS_ADD_SUS_MEMFD, ret);
        return ret;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* enable_avc_log_spoofing (v1.5.10+)                                  */
/* ------------------------------------------------------------------ */
int cmd_enable_avc_log_spoofing(int enabled) {
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
int cmd_show(const char *what) {
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
             * The bit positions for features are stable across these versions, but the
             * features themselves may differ, hence one name table per version.
             */
            const char **names = (g_version == 153) ? g_feature_names_153
                                : (g_version == 154) ? g_feature_names_154
                                : g_feature_names_158;
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

int cmd_sus_su(const char *arg) {
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
