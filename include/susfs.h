/*
 * susfs.h - shared declarations for the ksu_susfs universal userspace tool.
 *
 * Supports all susfs kernel versions v1.5.2 through v2.1.0 in a SINGLE binary.
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
 *   152, 153, 154, 158, 159, 1510, 1511, 1512, 2000, 2100
 *   (154 covers v1.5.4-v1.5.7; 1510 covers v1.5.10 and v1.5.11)
 */

#ifndef KSU_SUSFS_H
#define KSU_SUSFS_H

#include <stdbool.h>
#include <sys/stat.h>

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
#define CMD_SUSFS_ADD_SUS_MEMFD                  0x60030 /* Exclusive feature based on v1.3.8 susfs*/

/* v2.1.0 new kstat definitions */
#define KSTAT_SPOOF_INO (1 << 0)
#define KSTAT_SPOOF_DEV (1 << 1)
#define KSTAT_SPOOF_NLINK (1 << 2)
#define KSTAT_SPOOF_SIZE (1 << 3)
#define KSTAT_SPOOF_ATIME_TV_SEC (1 << 4)
#define KSTAT_SPOOF_ATIME_TV_NSEC (1 << 5)
#define KSTAT_SPOOF_MTIME_TV_SEC (1 << 6)
#define KSTAT_SPOOF_MTIME_TV_NSEC (1 << 7)
#define KSTAT_SPOOF_CTIME_TV_SEC (1 << 8)
#define KSTAT_SPOOF_CTIME_TV_NSEC (1 << 9)
#define KSTAT_SPOOF_BLOCKS (1 << 10)
#define KSTAT_SPOOF_BLKSIZE (1 << 11)
#define KSTAT_AUTO_SPOOF (KSTAT_SPOOF_INO | KSTAT_SPOOF_DEV | KSTAT_SPOOF_ATIME_TV_SEC | KSTAT_SPOOF_ATIME_TV_NSEC | \
		    KSTAT_SPOOF_MTIME_TV_SEC | KSTAT_SPOOF_MTIME_TV_NSEC | KSTAT_SPOOF_CTIME_TV_SEC | KSTAT_SPOOF_CTIME_TV_NSEC | \
		    KSTAT_SPOOF_BLKSIZE | KSTAT_SPOOF_BLOCKS)
#define KSTAT_AUTO_SPOOF_FULL_CLONE (KSTAT_AUTO_SPOOF | KSTAT_SPOOF_NLINK | KSTAT_SPOOF_SIZE)

/* v2.0.0 error sentinel */
#define ERR_v2000_CMD_NOT_SUPPORTED  255

/* Persistent cache marker for v2.0.0 old sus_path layout */
#define SUS_PATH_LAYOUT_CACHE_DIR     "/data/adb/ksu/susfs4ksu"
#define SUS_PATH_LAYOUT_OLD_MARKER    "/data/adb/ksu/susfs4ksu/using_old_sus_path_layout"

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
#define ABI_v2000    2   /* v2.0.0+ */

extern int   g_abi;             /* ABI_* */
extern int   g_version;         /* e.g. 152, 153, 154, 158, 159, 1510, 1511, 1512, 2000, 2100 */
extern char *g_version_string;  /* e.g. "v1.5.2", "v1.5.4", "v2.0.0" */

/* Runtime-detected v2.0.0 SUS_PATH ABI layout. */
#define V2000_SUS_PATH_LAYOUT_UNKNOWN 0
#define V2000_SUS_PATH_LAYOUT_OLD     1
#define V2000_SUS_PATH_LAYOUT_NEW     2
extern int g_v2000_sus_path_layout;

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

/* Old v2.0.0 kernel: has target_ino and i_uid */
struct sus_path_v2000 {
    unsigned long   target_ino;
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
    unsigned int    i_uid;
    int             err;
};

/* New v2.0.0 kernel: target_ino and i_uid removed, kernel resolves them itself */
struct sus_path_v2000_new {
    char            target_pathname[SUSFS_MAX_LEN_PATHNAME];
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

struct sus_kstat_v2100 {
    bool                    is_statically;
	unsigned long           target_ino;
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned long           spoofed_ino;
	unsigned long           spoofed_dev;
	unsigned int            spoofed_nlink;
	long long               spoofed_size;
	long                    spoofed_atime_tv_sec;
	unsigned long           spoofed_atime_tv_nsec;
	long                    spoofed_mtime_tv_sec;
	unsigned long           spoofed_mtime_tv_nsec;
	long                    spoofed_ctime_tv_sec;
	unsigned long           spoofed_ctime_tv_nsec;
	long long               spoofed_blocks;
	long                    spoofed_blksize;
	int                     flags;
	int                     err;
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

enum UID_SCHEME {
	UID_NON_APP_PROC = 0,
	UID_ROOT_PROC_EXCEPT_SU_PROC,
	UID_NON_SU_PROC,
	UID_UMOUNTED_APP_PROC,
	UID_UMOUNTED_PROC,
};

struct open_redirect_v2100 {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	char                    redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                     uid_scheme;
	int                     err;
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

/* sus_memfd exclusive feature */
struct sus_memfd_v1 {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
};

struct sus_memfd_v2000 {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
    int                     err;
};

/***************************
 ** Low-level IPC helpers **
 ** (src/ipc/ipc.c)        **
 ***************************/

/* Dispatch a command via the prctl ABI; returns value written to *error (0=OK, -1=unsupported). */
int  prctl_cmd(unsigned long cmd, void *arg);
/* prctl variant for scalar (non-pointer) third argument */
int  prctl_cmd_scalar(unsigned long cmd, unsigned long val);
/* prctl variant with explicit 4th arg (e.g. SHOW_ENABLED_FEATURES passes bufsize) */
int  prctl_cmd4(unsigned long cmd, void *arg3, unsigned long arg4);
/* Dispatch a command via the v2.0.0 syscall ABI. */
void v2000_cmd(unsigned long cmd, void *info);
/* Print unified "not supported" message. */
void prt_not_supported(unsigned long cmd, int err);

/****************************
 ** Version / feature detect **
 ** (src/detect/version.c) **
 ****************************/

int   parse_version_string(const char *s);
void  detect_susfs_version(void);
/*
 * Returns a newline-joined, cached string of the CONFIG_KSU_SUSFS_* names
 * currently enabled in the kernel, or NULL if unavailable.
 */
char *get_enabled_features_string(void);
/* True when the kernel reports the given CONFIG_KSU_SUSFS_* feature as enabled. */
bool  have_susfs_feature(const char *feature);

/* Bit-position -> CONFIG_KSU_SUSFS_* name tables for the v1.5.3-v1.5.8 buckets. */
extern const char *g_feature_names_153[];
extern const char *g_feature_names_154[];
extern const char *g_feature_names_158[];

/***********************
 ** Utility helpers    **
 ** (src/util/util.c)  **
 ***********************/

void pre_check(void);
int  get_file_stat(const char *pathname, struct stat *sb);
void copy_stat_to_kstat_v1(struct sus_kstat_v1 *k, const struct stat *sb);
void copy_stat_to_kstat_v2000(struct sus_kstat_v2000 *k, const struct stat *sb);
void copy_stat_to_kstat_v2100(struct sus_kstat_v2100 *k, const struct stat *sb);
/* Read a file into a malloc'd buffer (null-terminated). Caller must free(). */
int  read_file_to_buf(const char *path, char **out, long *out_size);

/* v2.0.0 sus_path layout cache (src/util/util.c) */
void load_sus_path_layout_cache(void);
void persist_old_sus_path_layout_cache(void);
void clear_old_sus_path_layout_cache(void);

/***********************
 ** Help              **
 ** (src/help/help.c) **
 ***********************/
void print_help(void);
int  print_more_help(const char *cmd);

/***************************
 ** Command implementations **
 ** (src/commands/commands.c) **
 ***************************/
int cmd_add_sus_path(const char *path, bool loop);
int cmd_set_external_dir(const char *path, unsigned long cmd);
int cmd_add_sus_mount(const char *path);
int cmd_hide_sus_mnts(int enabled);
int cmd_umount_zygote_iso(int enabled);
int cmd_add_sus_kstat_statically(char **argv);
int cmd_add_sus_kstat(const char *path);
int cmd_update_sus_kstat(const char *path, bool full_clone);
int cmd_add_try_umount(const char *path, int mnt_mode);
int cmd_set_uname(const char *release, const char *version);
int cmd_enable_log(int enabled);
int cmd_set_cmdline_or_bootconfig(const char *filepath);
int cmd_add_open_redirect(const char *target, const char *redirect);
int cmd_add_open_redirect_2100(const char *target, const char *redirect, const char *uid);
int cmd_add_sus_map(const char *path);
int cmd_add_sus_memfd(const char *path);
int cmd_enable_avc_log_spoofing(int enabled);
int cmd_show(const char *what);
int cmd_sus_su(const char *arg);

#endif /* KSU_SUSFS_H */
