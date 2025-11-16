#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <android/log.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <sys/syscall.h>

/*************************
 ** Define Const Values **
 *************************/
#define TAG "ksu_susfs"
#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define SUSFS_MAGIC 0xFAFAFAFA

#define CMD_SUSFS_ADD_SUS_PATH 0x55550
#define CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH 0x55551
#define CMD_SUSFS_SET_SDCARD_ROOT_PATH 0x55552
#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553
#define CMD_SUSFS_ADD_SUS_MOUNT 0x55560
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS 0x55561
#define CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE 0x55562
#define CMD_SUSFS_ADD_SUS_KSTAT 0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT 0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY 0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT 0x55580
#define CMD_SUSFS_SET_UNAME 0x55590
#define CMD_SUSFS_ENABLE_LOG 0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT 0x555c0
#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT 0x555e3
#define CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE 0x555e4 /* deprecated */
#define CMD_SUSFS_IS_SUS_SU_READY 0x555f0 /* deprecated */
#define CMD_SUSFS_SUS_SU 0x60000 /* deprecated */
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING 0x60010
#define CMD_SUSFS_ADD_SUS_MAP 0x60020

#define SUSFS_MAX_LEN_PATHNAME 256
#define SUSFS_MAX_LEN_MOUNT_TYPE_NAME 32
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192
#define SUSFS_ENABLED_FEATURES_SIZE 8192
#define SUSFS_MAX_VERSION_BUFSIZE 16
#define SUSFS_MAX_VARIANT_BUFSIZE 16

#ifndef __NEW_UTS_LEN
#define __NEW_UTS_LEN 64
#endif

/* VM flags from linux kernel */
#define VM_NONE		0x00000000
#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008
/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

/******************
 ** Define Macro **
 ******************/
#define ERR_CMD_NOT_SUPPORTED 255
#define log(fmt, msg...) printf(fmt, ##msg);
#define PRT_MSG_IF_CMD_NOT_SUPPORTED(x, cmd) if (x == ERR_CMD_NOT_SUPPORTED) log("[-] CMD: '0x%x', SUSFS operation not supported, please enable it in kernel\n", cmd)

/*******************
 ** Define Struct **
 *******************/
struct st_susfs_sus_path {
	unsigned long           target_ino;
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned int            i_uid;
	int                     err;
};

struct st_external_dir {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	bool                    is_inited;
	int                     cmd;
	int                     err;
};

struct st_susfs_sus_mount {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned long           target_dev;
	int                     err;
};

struct st_susfs_hide_sus_mnts_for_all_procs {
	bool                    enabled;
	int                     err;
};

struct st_susfs_umount_for_zygote_iso_service {
	bool                    enabled;
	int                     err;
};

struct st_susfs_sus_kstat {
	bool                    is_statically;
	unsigned long           target_ino; // the ino after bind mounted or overlayed
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned long           spoofed_ino;
	unsigned long           spoofed_dev;
	unsigned int            spoofed_nlink;
	long long               spoofed_size;
	long                    spoofed_atime_tv_sec;
	long                    spoofed_mtime_tv_sec;
	long                    spoofed_ctime_tv_sec;
	long                    spoofed_atime_tv_nsec;
	long                    spoofed_mtime_tv_nsec;
	long                    spoofed_ctime_tv_nsec;
	unsigned long           spoofed_blksize;
	unsigned long long      spoofed_blocks;
	int                     err;
};

struct st_susfs_try_umount {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                     mnt_mode;
	int                     err;
};

struct st_susfs_uname {
	char                    release[__NEW_UTS_LEN+1];
	char                    version[__NEW_UTS_LEN+1];
	int                     err;
};

struct st_susfs_log {
	bool                    enabled;
	int                     err;
};

struct st_susfs_spoof_cmdline_or_bootconfig {
	char                    fake_cmdline_or_bootconfig[SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
	int                     err;
};

struct st_susfs_open_redirect {
	unsigned long           target_ino;
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	char                    redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                     err;
};

struct st_susfs_sus_map {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                     err;
};

struct st_susfs_avc_log_spoofing {
	bool                    enabled;
	int                     err;
};

struct st_susfs_enabled_features {
	char                    enabled_features[SUSFS_ENABLED_FEATURES_SIZE];
	int                     err;
};

struct st_susfs_variant {
	char                    susfs_variant[SUSFS_MAX_VARIANT_BUFSIZE];
	int                     err;
};

struct st_susfs_version {
	char                    susfs_version[SUSFS_MAX_VERSION_BUFSIZE];
	int                     err;
};

/**********************
 ** Define Functions **
 **********************/
void pre_check() {
	if (getuid() != 0) {
		log("[-] Must run as root\n");
		exit(1);
	}
}

int isNumeric(char* str) {
	// Check if the string is empty
	if (str[0] == '\0') {
		return 0;
	}

	// Check each character in the string
	for (int i = 0; str[i] != '\0'; i++) {
		// If any character is not a digit, return false
		if (!isdigit(str[i])) {
			return 0;
		}
	}

	// All characters are digits, return true
	return 1;
}

int get_file_stat(char *pathname, struct stat* sb) {
	if (stat(pathname, sb) != 0) {
		return errno;
	}
	return 0;
}

void copy_stat_to_sus_kstat(struct st_susfs_sus_kstat* info, struct stat* sb) {
	info->spoofed_ino = sb->st_ino;
	info->spoofed_dev = sb->st_dev;
	info->spoofed_nlink = sb->st_nlink;
	info->spoofed_size = sb->st_size;
	info->spoofed_atime_tv_sec = sb->st_atime;
	info->spoofed_mtime_tv_sec = sb->st_mtime;
	info->spoofed_ctime_tv_sec = sb->st_ctime;
	info->spoofed_atime_tv_nsec = sb->st_atime_nsec;
	info->spoofed_mtime_tv_nsec = sb->st_mtime_nsec;
	info->spoofed_ctime_tv_nsec = sb->st_ctime_nsec;
	info->spoofed_blksize = sb->st_blksize;
	info->spoofed_blocks = sb->st_blocks;
}


static void print_help(void) {
	log("usage: %s <CMD> [CMD options]\n", TAG);
	log("  <CMD>:\n");
	log("    add_sus_path </path/of/file_or_directory>\n");
	log("      |--> Added path and all its sub-paths will be hidden from several syscalls\n");
	log("      |--> Please be reminded that the target path must be added after the bind mount or overlay operation if any, otherwise it won't be effective\n");
	log("      |--> To fix the leak of app path after /sdcard/Android/data from syscall, please run ksu_susfs set_android_data_root_path </path/of/sdcard/Android/data> first\n");
	log("      |--> To hide paths after /sdcard/, please run ksu_susfs set_sdcard_root_path </root/dir/of/sdcard> first\n");
	log("\n");
	log("    add_sus_path_loop </path/not/inside/sdcard>\n");
	log("      |--> The only different to add_sus_path is the added sus_path will be flagged as SUS_PATH again per each zygote spawned non-rooted process\n");
	log("      |--> This applies to regular path (not including path in /sdcard/) only\n");
	log("\n");
	log("    set_android_data_root_path </root/dir/of/sdcard/Android/data>\n");
	log("      |--> To fix the leak of app path after /sdcard/Android/data/ from syscall, first you need to tell the susfs kernel where is the actual path '/sdcard/Android/data' located, as it may vary on different phones\n");
	log("      |--> Effective for no root access granted user apps only\n");
	log("\n");
	log("    set_sdcard_root_path </root/dir/of/sdcard>\n");
	log("      |--> To hide paths after /sdcard/, first you need to tell the susfs kernel where is the actual path '/sdcard' located, as it may vary on different phones\n");
	log("      |--> Warning: All no root access granted user apps cannot see any sus paths in /sdcard/ unless you grant root access for the target app\n");
	log("\n");
	log("    add_sus_mount <mounted_path>\n");
	log("      |--> Added mounted path will be hidden from /proc/self/[mounts|mountinfo|mountstats]\n");
	log("      |--> Please be reminded that the target path must be added after the bind mount or overlay operation, otherwise it won't be effective\n");
	log("\n");
	log("    hide_sus_mnts_for_all_procs <0|1>\n");
	log("      |--> 0 -> Do not hide sus mounts for all processes but only non ksu process\n");
	log("      |--> 1 -> Hide all sus mounts for all processes no matter they are ksu processes or not\n");
	log("      |--> NOTE:\n");
	log("           - It is set to 1 in kernel by default\n");
	log("           - It is recommended to set to 0 after screen is unlocked, or during service.sh or boot-completed.sh stage, as this should fix the issue on some rooted apps that rely on mounts mounted by ksu process\n");
	log("\n");
	log("    umount_for_zygote_iso_service <0|1>\n");
	log("      |--> 0 -> Do not umount for zygote spawned isolated service process\n");
	log("      |--> 1 -> Enable to umount for zygote spawned isolated service process\n");
	log("      |--> NOTE:\n");
	log("           - By default it is set to 0 in kernel, or create '/data/adb/susfs_umount_for_zygote_iso_service' to set it to 1 on boot\n");
	log("           - Set to 0 if you have modules that overlay framework system files like framework.jar or other overlay apk, then atm you should let other module like zygisk and its hiding module to take care of, otherwise it may cause bootloop\n");
	log("           - Set to 1 if you DO NOT have such modules mentioned above, otherwise sus mounts won't be umounted for zygote spawned isolated process and they will be detected\n");
	log("\n");
	log("    add_sus_kstat_statically </path/of/file_or_directory> <ino> <dev> <nlink> <size> <atime> <atime_nsec> <mtime> <mtime_nsec> <ctime> <ctime_nsec> <blocks> <blksize>\n");
	log("      |--> Use 'stat' tool to find the format:\n");
	log("               ino -> %%i, dev -> %%d, nlink -> %%h, atime -> %%X, mtime -> %%Y, ctime -> %%Z\n");
	log("               size -> %%s, blocks -> %%b, blksize -> %%B\n");
	log("      |--> e.g., %s add_sus_kstat_statically '/system/addon.d' '1234' '1234' '2' '223344'\\\n", TAG);
	log("                    '1712592355' '0' '1712592355' '0' '1712592355' '0' '1712592355' '0'\\\n");
	log("                    '16' '512'\n");
	log("      |--> Or pass 'default' to use its original value:\n");
	log("      |--> e.g., %s add_sus_kstat_statically '/system/addon.d' 'default' 'default' 'default' 'default'\\\n", TAG);
	log("                    '1712592355' 'default' '1712592355' 'default' '1712592355' 'default'\\\n");
	log("                    'default' 'default'\n");
	log("\n");
	log("    add_sus_kstat </path/of/file_or_directory>\n");
	log("      |--> Add the desired path BEFORE it gets bind mounted or overlayed, this is used for storing original stat info in kernel memory\n");
	log("      |--> This command must be completed with <update_sus_kstat> later after the added path is bind mounted or overlayed\n");
	log("\n");
	log("    update_sus_kstat </path/of/file_or_directory>\n");
	log("      |--> Add the desired path you have added before via <add_sus_kstat> to complete the kstat spoofing procedure\n");
	log("      |--> This updates the target ino, but size and blocks are remained the same as current stat\n");
	log("\n");
	log("    update_sus_kstat_full_clone </path/of/file_or_directory>\n");
	log("      |--> Add the desired path you have added before via <add_sus_kstat> to complete the kstat spoofing procedure\n");
	log("      |--> This updates the target ino only, other stat members are remained the same as the original stat\n");
	log("\n");
	log("    add_try_umount </path/of/file_or_directory> <mode>\n");
	log("      |--> Added path will be umounted from KSU for all UIDs that are NOT su allowed, and profile template configured with umount\n");
	log("      |--> <mode>: 0 -> umount with no flags, 1 -> umount with MNT_DETACH\n");
	log("      |--> NOTE: susfs umount takes precedence of ksu umount\n");
	log("\n");
	log("    set_uname <release> <version>\n");
	log("      |--> NOTE: Only 'release' and <version> are spoofed as others are no longer needed\n");
	log("      |--> Spoof uname for all processes, set string to 'default' to imply the function to use original string\n");
	log("      |--> e.g., set_uname '4.9.337-g3291538446b7' 'default'\n");
	log("\n");
	log("    enable_log <0|1>\n");
	log("      |--> 0: disable susfs log in kernel, 1: enable susfs log in kernel\n");
	log("\n");
	log("    set_cmdline_or_bootconfig </path/to/fake_cmdline_file/or/fake_bootconfig_file>\n");
	log("      |--> Spoof the output of /proc/cmdline (non-gki) or /proc/bootconfig (gki) from a text file\n");
	log("\n");
	log("    add_open_redirect </target/path> </redirected/path>\n");
	log("      |--> Redirect the target path to be opened with user defined path\n");
	log("\n");
	log("    add_sus_map </path/to/actual/library>\n");
	log("      |--> Added real file path which gets mmapped will be hidden from /proc/self/[maps|smaps|smaps_rollup|map_files|mem|pagemap]\n");
	log("      |--> e.g., add_sus_map '/data/adb/modules/my_module/zygisk/arm64-v8a.so'\n");
	log("      * Important Note *\n");
	log("      - It does NOT support hiding for anon memory.\n");
	log("      - It does NOT hide any inline hooks or plt hooks cause by the injected library itself\n");
	log("      - It may not be able to evade detections by apps that implement a good injection detection\n");
	log("\n");
	log("    enable_avc_log_spoofing <0|1>\n");
	log("      |--> 0: Disable spoofing the sus 'su' tcontext shown in avc log in kernel\n");
	log("      |--> 1: Enable spoofing the sus tcontext 'su' with 'kernel' shown in avc log in kernel\n");
	log("      * Important Note *\n");
	log("      - It is set to '0' by default in kernel\n");
	log("      - Enable this will sometimes make developers hard to identify the cause when they are debugging with some permission or selinux issue, so users are advised to disbale this when doing so.\n");
	log("\n");
	log("    show <version|enabled_features|variant>\n");
	log("      |--> version: show the current susfs version implemented in kernel\n");
	log("      |--> enabled_features: show the current implemented susfs features in kernel\n");
	log("      |--> variant: show the current variant: GKI or NON-GKI\n");
	log("\n");
}

/*******************
 ** Main Function **
 *******************/
int main(int argc, char *argv[]) {
	pre_check();
	// add_sus_path
	if (argc == 3 && !strcmp(argv[1], "add_sus_path")) {
		struct st_susfs_sus_path info = {0};
		struct stat sb;

		info.err = get_file_stat(argv[2], &sb);
		if (info.err) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return info.err;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.target_ino = sb.st_ino;
		info.i_uid = sb.st_uid;
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_PATH, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_SUS_PATH);
		return info.err;
	// add_sus_path_loop
	} else if (argc == 3 && !strcmp(argv[1], "add_sus_path_loop")) {
		struct st_susfs_sus_path info = {0};
		struct stat sb;

		info.err = get_file_stat(argv[2], &sb);
		if (info.err) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return info.err;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.target_ino = sb.st_ino;
		info.i_uid = sb.st_uid;
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_PATH_LOOP, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_SUS_PATH_LOOP);
		return info.err;
	// set_android_data_root_path
	} else if (argc == 3 && !strcmp(argv[1], "set_android_data_root_path")) {
		struct st_external_dir info = {0};

		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.cmd = CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH;
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH);
		return info.err;
	// set_sdcard_root_path
	} else if (argc == 3 && !strcmp(argv[1], "set_sdcard_root_path")) {
		struct st_external_dir info = {0};

		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.err = ERR_CMD_NOT_SUPPORTED;
		info.cmd = CMD_SUSFS_SET_SDCARD_ROOT_PATH;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SET_SDCARD_ROOT_PATH, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_SET_SDCARD_ROOT_PATH);
		return info.err;
	// add_sus_mount
	} else if (argc == 3 && !strcmp(argv[1], "add_sus_mount")) {
		struct st_susfs_sus_mount info = {0};
		struct stat sb;

		info.err = get_file_stat(argv[2], &sb);
		if (info.err) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return info.err;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.target_dev = sb.st_dev;
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_MOUNT, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_SUS_MOUNT);
		return info.err;
	// hide_sus_mnts_for_all_procs
	} else if (argc == 3 && !strcmp(argv[1], "hide_sus_mnts_for_all_procs")) {
		struct st_susfs_hide_sus_mnts_for_all_procs info = {0};

		if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
			print_help();
			return 1;
		}
		info.enabled = atoi(argv[2]);
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS);
		return info.err;
	// umount_for_zygote_iso_service
	} else if (argc == 3 && !strcmp(argv[1], "umount_for_zygote_iso_service")) {
		struct st_susfs_umount_for_zygote_iso_service info = {0};

		if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
			print_help();
			return -EINVAL;
		}
		info.enabled = atoi(argv[2]);
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE);
		return info.err;
	// add_sus_kstat_statically
	} else if (argc == 15 && !strcmp(argv[1], "add_sus_kstat_statically")) {
		struct st_susfs_sus_kstat info = {0};
		struct stat sb;
		char* endptr;
		unsigned long ino, dev, nlink, size, atime, atime_nsec, mtime, mtime_nsec, ctime, ctime_nsec, blksize;
		long blocks;

		info.err = get_file_stat(argv[2], &sb);
		if (info.err) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return info.err;
		}
		
		info.is_statically = true;
		/* ino */
		if (strcmp(argv[3], "default")) {
			ino = strtoul(argv[3], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			info.target_ino = sb.st_ino;
			sb.st_ino = ino;
		} else {
			info.target_ino = sb.st_ino;
		}
		/* dev */
		if (strcmp(argv[4], "default")) {
			dev = strtoul(argv[4], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_dev = dev;
		}
		/* nlink */
		if (strcmp(argv[5], "default")) {
			nlink = strtoul(argv[5], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_nlink = nlink;
		}
		/* size */
		if (strcmp(argv[6], "default")) {
			size = strtoul(argv[6], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_size = size;
		}
		/* atime */
		if (strcmp(argv[7], "default")) {
			atime = strtol(argv[7], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_atime = atime;
		}
		/* atime_nsec */
		if (strcmp(argv[8], "default")) {
			atime_nsec = strtoul(argv[8], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_atimensec = atime_nsec;
		}
		/* mtime */
		if (strcmp(argv[9], "default")) {
			mtime = strtol(argv[9], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_mtime = mtime;
		}
		/* mtime_nsec */
		if (strcmp(argv[10], "default")) {
			mtime_nsec = strtoul(argv[10], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_mtimensec = mtime_nsec;
		}
		/* ctime */
		if (strcmp(argv[11], "default")) {
			ctime = strtol(argv[11], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_ctime = ctime;
		}
		/* ctime_nsec */
		if (strcmp(argv[12], "default")) {
			ctime_nsec = strtoul(argv[12], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_ctimensec = ctime_nsec;
		}
		/* blocks */
		if (strcmp(argv[13], "default")) {
			blocks = strtoul(argv[13], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_blocks = blocks;
		}
		/* blksize */
		if (strcmp(argv[14], "default")) {
			blksize = strtoul(argv[14], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return -EINVAL;
			}
			sb.st_blksize = blksize;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		copy_stat_to_sus_kstat(&info, &sb);
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY);
		return info.err;
	// add_sus_kstat
	} else if (argc == 3 && !strcmp(argv[1], "add_sus_kstat")) {
		struct st_susfs_sus_kstat info = {0};
		struct stat sb;

		info.err = get_file_stat(argv[2], &sb);
		if (info.err) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return info.err;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.is_statically = false;
		info.target_ino = sb.st_ino;
		copy_stat_to_sus_kstat(&info, &sb);
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_KSTAT, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_SUS_KSTAT);
		return info.err;
	// update_sus_kstat
	} else if (argc == 3 && !strcmp(argv[1], "update_sus_kstat")) {
		struct st_susfs_sus_kstat info = {0};
		struct stat sb;

		info.err = get_file_stat(argv[2], &sb);
		if (info.err) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return info.err;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.is_statically = false;
		info.target_ino = sb.st_ino;
		info.spoofed_size = sb.st_size; // use the current size, not the spoofed one
		info.spoofed_blocks = sb.st_blocks; // use the current blocks, not the spoofed one
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_UPDATE_SUS_KSTAT, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_UPDATE_SUS_KSTAT);
		return info.err;
	// update_sus_kstat_full_clone
	} else if (argc == 3 && !strcmp(argv[1], "update_sus_kstat_full_clone")) {
		struct st_susfs_sus_kstat info = {0};
		struct stat sb;

		info.err = get_file_stat(argv[2], &sb);
		if (info.err) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return info.err;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.is_statically = false;
		info.target_ino = sb.st_ino;
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_UPDATE_SUS_KSTAT, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_UPDATE_SUS_KSTAT);
		return info.err;
	// add_try_umount
	} else if (argc == 4 && !strcmp(argv[1], "add_try_umount")) {
		struct st_susfs_try_umount info = {0};
		char* endptr;
		char abs_path[PATH_MAX], *p_abs_path;
		
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		p_abs_path = realpath(info.target_pathname, abs_path);
		if (p_abs_path == NULL) {
			perror("realpath");
			return errno;
		}
		if (!strcmp(p_abs_path, "/odm") ||
			!strcmp(p_abs_path, "/system") ||
			!strcmp(p_abs_path, "/vendor") ||
			!strcmp(p_abs_path, "/product") ||
			!strcmp(p_abs_path, "/system_ext") ||
			!strcmp(p_abs_path, "/data/adb/modules")) {
			log("[-] %s cannot be added to try_umount, because it will be umounted by ksu lastly\n", p_abs_path);
			return -EINVAL;
		}
		if (strcmp(argv[3], "0") && strcmp(argv[3], "1")) {
			print_help();
			return -EINVAL;
		}
		info.mnt_mode = strtol(argv[3], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_TRY_UMOUNT, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_TRY_UMOUNT);
		return info.err;
	// set_uname
	} else if (argc == 4 && !strcmp(argv[1], "set_uname")) {
		struct st_susfs_uname info = {0};
		
		strncpy(info.release, argv[2], __NEW_UTS_LEN);
		strncpy(info.version, argv[3], __NEW_UTS_LEN);
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SET_UNAME, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_SET_UNAME);
		return info.err;
	// enable_log
	} else if (argc == 3 && !strcmp(argv[1], "enable_log")) {
		struct st_susfs_log info = {0};

		if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
			print_help();
			return -EINVAL;
		}
		info.enabled = atoi(argv[2]);
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ENABLE_LOG, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ENABLE_LOG);
		return info.err;
	// set_cmdline_or_bootconfig
	} else if (argc == 3 && !strcmp(argv[1], "set_cmdline_or_bootconfig")) {
		struct st_susfs_spoof_cmdline_or_bootconfig *info = malloc(sizeof(struct st_susfs_spoof_cmdline_or_bootconfig));
		char abs_path[PATH_MAX], *p_abs_path;
		FILE *file;
		long file_size;
		size_t read_size; 
		int err = 0;

		if (!info) {
			perror("malloc");
			return -ENOMEM;
		}
		memset(info, 0, sizeof(struct st_susfs_spoof_cmdline_or_bootconfig));
		p_abs_path = realpath(argv[2], abs_path);
		if (p_abs_path == NULL) {
			perror("realpath");
			free(info);
			return errno;
		}
		file = fopen(abs_path, "rb");
		if (file == NULL) {
			perror("Error opening file");
			free(info);
			return errno;
		}
		fseek(file, 0, SEEK_END);
		file_size = ftell(file);
		if (file_size >= SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE) {
			perror("file_size too long");
			free(info);
			return -EINVAL;
		}
		rewind(file);
		read_size = fread(info->fake_cmdline_or_bootconfig, 1, file_size, file);
		if (read_size != file_size) {
			perror("Reading error");
			fclose(file);
			free(info);
			return -EFAULT;
		}
		fclose(file);
		info->fake_cmdline_or_bootconfig[file_size] = '\0';
		info->err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG, info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info->err, CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG);
		err = info->err;
		free(info);
		return err;
	// add_open_redirect
	} else if (argc == 4 && !strcmp(argv[1], "add_open_redirect")) {
		struct st_susfs_open_redirect info = {0};
		struct stat sb;
		char target_pathname[PATH_MAX], *p_abs_target_pathname;
		char redirected_pathname[PATH_MAX], *p_abs_redirected_pathname;

		p_abs_target_pathname = realpath(argv[2], target_pathname);
		if (p_abs_target_pathname == NULL) {
			perror("realpath");
			return errno;
		}
		strncpy(info.target_pathname, target_pathname, SUSFS_MAX_LEN_PATHNAME-1);
		p_abs_redirected_pathname = realpath(argv[3], redirected_pathname);
		if (p_abs_redirected_pathname == NULL) {
			perror("realpath");
			return errno;
		}
		strncpy(info.redirected_pathname, redirected_pathname, SUSFS_MAX_LEN_PATHNAME-1);
		info.err = get_file_stat(info.target_pathname, &sb);
		if (info.err) {
			log("[-] Failed to get stat from path: '%s'\n", info.target_pathname);
			return info.err;
		}
		info.target_ino = sb.st_ino;
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_OPEN_REDIRECT, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_OPEN_REDIRECT);
		return info.err;
	// add_sus_map
	} else if (argc == 3 && !strcmp(argv[1], "add_sus_map")) {
		struct st_susfs_sus_map info = {0};

		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ADD_SUS_MAP, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ADD_SUS_MAP);
		return info.err;
	// enable_avc_log_spoofing
	} else if (argc == 3 && !strcmp(argv[1], "enable_avc_log_spoofing")) {
		struct st_susfs_avc_log_spoofing info = {0};

		if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
			print_help();
			return -EINVAL;
		}
		info.enabled = atoi(argv[2]);
		info.err = ERR_CMD_NOT_SUPPORTED;
		syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING, &info);
		PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING);
		return info.err;
	// show
	} else if (argc == 3 && !strcmp(argv[1], "show")) {
		if (!strcmp(argv[2], "version")) {
			struct st_susfs_version info = {0};

			info.err = ERR_CMD_NOT_SUPPORTED;
			syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_VERSION, &info);
			PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_SHOW_VERSION);
			if (!info.err)
				printf("%s\n", info.susfs_version);
			return info.err;
		} else if (!strcmp(argv[2], "enabled_features")) {
			struct st_susfs_enabled_features *info = malloc(sizeof(struct st_susfs_enabled_features));
			int err = 0;

			if (!info) {
				perror("malloc");
				return -ENOMEM;
			}
			memset(info, 0, sizeof(struct st_susfs_enabled_features));
			info->err = ERR_CMD_NOT_SUPPORTED;
			syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_ENABLED_FEATURES, info);
			PRT_MSG_IF_CMD_NOT_SUPPORTED(info->err, CMD_SUSFS_SHOW_ENABLED_FEATURES);
			if (!info->err) {
				printf("%s", info->enabled_features); // no new line is needed
			}
			err = info->err;
			free(info);
			return err;
		} else if (!strcmp(argv[2], "variant")) {
			struct st_susfs_variant info = {0};

			info.err = ERR_CMD_NOT_SUPPORTED;
			syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_VARIANT, &info);
			PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_SHOW_VARIANT);
			if (!info.err)
				printf("%s\n", info.susfs_variant);
			return info.err;
		} else {
			print_help();
		}
	} else {
		print_help();
	}
out:
	return 0;
}