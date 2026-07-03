/*
 * util.c - assorted userspace helpers: root check, stat/kstat copying,
 * file reading, and the v2.0.0 sus_path layout cache.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "susfs.h"

void pre_check(void) {
    if (getuid() != 0) {
        printf("[-] Must run as root\n");
        exit(1);
    }
}

int get_file_stat(const char *pathname, struct stat *sb) {
    return stat(pathname, sb) != 0;
}

void copy_stat_to_kstat_v1(struct sus_kstat_v1 *k, const struct stat *sb) {
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

void copy_stat_to_kstat_v2000(struct sus_kstat_v2000 *k, const struct stat *sb) {
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

void copy_stat_to_kstat_v2100(struct sus_kstat_v2100 *k, const struct stat *sb) {
    k->spoofed_ino           = sb->st_ino;
    k->spoofed_dev           = sb->st_dev;
    k->spoofed_nlink         = sb->st_nlink;
    k->spoofed_size          = sb->st_size;
    k->spoofed_atime_tv_sec  = sb->st_atime;
    k->spoofed_atime_tv_nsec = sb->st_atimensec;
    k->spoofed_mtime_tv_sec  = sb->st_mtime;
    k->spoofed_mtime_tv_nsec = sb->st_mtimensec;
    k->spoofed_ctime_tv_sec  = sb->st_ctime;
    k->spoofed_ctime_tv_nsec = sb->st_ctimensec;
    k->spoofed_blocks        = sb->st_blocks;
    k->spoofed_blksize       = sb->st_blksize;
}

/* Read a file into a malloc'd buffer (null-terminated). Caller must free(). */
int read_file_to_buf(const char *path, char **out, long *out_size) {
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

/***********************************
 ** v2.0.0 sus_path layout cache  **
 ***********************************/

void load_sus_path_layout_cache(void) {
    if ((g_abi != ABI_v2000) || HAVE(2100))
        return;
    if (access(SUS_PATH_LAYOUT_OLD_MARKER, F_OK) == 0)
        g_v2000_sus_path_layout = V2000_SUS_PATH_LAYOUT_OLD;
}

void persist_old_sus_path_layout_cache(void) {
    int fd;
    /* Best-effort cache directory creation. */
    (void)mkdir(SUS_PATH_LAYOUT_CACHE_DIR, 0755);
    fd = open(SUS_PATH_LAYOUT_OLD_MARKER, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open(layout_cache)");
        return;
    }
    close(fd);
}

void clear_old_sus_path_layout_cache(void) {
    (void)unlink(SUS_PATH_LAYOUT_OLD_MARKER);
}
