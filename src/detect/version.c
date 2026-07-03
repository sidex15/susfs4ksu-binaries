/*
 * version.c - runtime susfs version/ABI detection and feature querying.
 *
 * Also holds the definitions of the process-wide runtime state globals
 * (g_abi, g_version, g_version_string, g_v2000_sus_path_layout).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "susfs.h"

/***************************
 ** Runtime version state **
 ***************************/
int   g_abi     = ABI_UNKNOWN;
int   g_version = 0;
char *g_version_string = NULL;
int   g_v2000_sus_path_layout = V2000_SUS_PATH_LAYOUT_UNKNOWN;

/*
 * Maps a parsed "X.Y.Z" to the internal ABI bucket it belongs to.
 * Ordered newest -> oldest; the first entry whose (major, minor, patch_min)
 * is satisfied is the bucket used. This means any version newer than the
 * newest known entry (e.g. a future v2.2.0 or v3.0.0) falls through to that
 * newest bucket instead of being mis-routed into an older version's logic.
 */
static const struct { int major, minor, patch_min, bucket; } g_version_table[] = {
    { 2, 1, 0,  2100 },
    { 2, 0, 0,  2000 },
    { 1, 5, 12, 1512 },
    { 1, 5, 10, 1510 },   /* covers 1.5.10 and 1.5.11 */
    { 1, 5, 9,  159  },
    { 1, 5, 8,  158  },
    { 1, 5, 4,  154  },   /* covers 1.5.4 - 1.5.7 */
    { 1, 5, 3,  153  },
    { 1, 5, 2,  152  },
};

/*
 * Bit-position -> CONFIG_KSU_SUSFS_* name tables for the v1.5.3-v1.5.8 bucket,
 * where CMD_SUSFS_SHOW_ENABLED_FEATURES returns an integer bitmask instead of
 * a human-readable string. Bit positions are stable across these versions,
 * but the feature set at each bit differs, hence one table per version.
 */
const char *g_feature_names_153[] = {
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
const char *g_feature_names_154[] = {
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
const char *g_feature_names_158[] = {
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

int parse_version_string(const char *s) {
    int ma = 0, mi = 0, pa = 0;
    if (sscanf(s, "v%d.%d.%d", &ma, &mi, &pa) != 3)
        return 0;

    for (size_t i = 0; i < sizeof(g_version_table) / sizeof(g_version_table[0]); i++) {
        const __typeof__(g_version_table[0]) *b = &g_version_table[i];
        if (ma > b->major ||
            (ma == b->major && mi > b->minor) ||
            (ma == b->major && mi == b->minor && pa >= b->patch_min))
            return b->bucket;
    }
    return 154; /* safe fallback */
}

void detect_susfs_version(void) {
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

/*
 * Returns a newline-joined, malloc'd string of the CONFIG_KSU_SUSFS_* names
 * currently enabled in the kernel, or NULL if the kernel has no
 * SHOW_ENABLED_FEATURES command (pre-v1.5.3) or the query failed. Fetched
 * once and cached for the life of the process.
 */
char *get_enabled_features_string(void) {
    static char *cache = NULL;
    static bool  fetched = false;
    if (fetched)
        return cache;
    fetched = true;

    if (g_abi == ABI_v2000) {
        struct enabled_features_v2000 info = {0};
        info.err = ERR_v2000_CMD_NOT_SUPPORTED;
        v2000_cmd(CMD_SUSFS_SHOW_ENABLED_FEATURES, &info);
        if (!info.err)
            cache = strdup(info.enabled_features);
    } else if (HAVE(159)) {
        size_t bufsz = (size_t)getpagesize() * 2;
        char *buf = malloc(bufsz);
        if (buf) {
            int r = prctl_cmd4(CMD_SUSFS_SHOW_ENABLED_FEATURES, buf, (unsigned long)bufsz);
            if (!r)
                cache = buf;
            else
                free(buf);
        }
    } else if (HAVE(153)) {
        /* v1.5.3-v1.5.8: kernel returns an integer bitmask, decode via name tables */
        unsigned long mask = 0;
        int r = prctl_cmd(CMD_SUSFS_SHOW_ENABLED_FEATURES, &mask);
        if (!r) {
            const char **names = (g_version == 153) ? g_feature_names_153
                                : (g_version == 154) ? g_feature_names_154
                                : g_feature_names_158;
            size_t cap = 4096, len = 0;
            char *buf = malloc(cap);
            if (buf) {
                buf[0] = '\0';
                for (int bit = 0; names[bit]; bit++) {
                    if (!(mask & (1UL << bit)))
                        continue;
                    size_t need = strlen(names[bit]) + 2;
                    if (len + need > cap) {
                        cap *= 2;
                        char *grown = realloc(buf, cap);
                        if (!grown) { free(buf); buf = NULL; break; }
                        buf = grown;
                    }
                    len += (size_t)sprintf(buf + len, "%s\n", names[bit]);
                }
                cache = buf;
            }
        }
    }
    return cache;
}

bool have_susfs_feature(const char *feature) {
    const char *features = get_enabled_features_string();
    if (!features)
        return false;

    size_t flen = strlen(feature);
    for (const char *p = features; (p = strstr(p, feature)) != NULL; p += flen) {
        bool start_ok = (p == features) || !(isalnum((unsigned char)p[-1]) || p[-1] == '_');
        bool end_ok   = !isalnum((unsigned char)p[flen]) && p[flen] != '_';
        if (start_ok && end_ok)
            return true;
    }
    return false;
}
