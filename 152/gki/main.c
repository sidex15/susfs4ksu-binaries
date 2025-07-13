#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <android/log.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>

/*************************
 ** Define Const Values **
 *************************/
#define TAG "ksu_susfs"
#define KERNEL_SU_OPTION 0xDEADBEEF

#define CMD_SUSFS_ADD_SUS_PATH 0x55550
#define CMD_SUSFS_ADD_SUS_MOUNT 0x55560
#define CMD_SUSFS_ADD_SUS_KSTAT 0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT 0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY 0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT 0x55580
#define CMD_SUSFS_SET_UNAME 0x55590
#define CMD_SUSFS_ENABLE_LOG 0x555a0
#define CMD_SUSFS_SET_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT 0x555c0
#define CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS 0x555d0
#define CMD_SUSFS_SUS_SU 0x60000

#define SUSFS_MAX_LEN_PATHNAME 256
#define SUSFS_MAX_LEN_MOUNT_TYPE_NAME 32

#ifndef __NEW_UTS_LEN
#define __NEW_UTS_LEN 64
#endif

#define SUS_SU_BIN_PATH "/data/adb/ksu/bin/sus_su"
#define SUS_SU_CONF_FILE_PATH "/data/adb/ksu/bin/sus_su_drv_path"
#define SUS_SU_WITH_OVERLAY 1
#define SUS_SU_WITH_HOOKS 2

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
#define log(fmt, msg...) printf(TAG ":" fmt, ##msg);
#define PRT_MSG_IF_OPERATION_NOT_SUPPORTED(x, cmd) if (x == -1) log("[-] CMD: '0x%x', SUSFS operation not supported, please enable it in kernel\n", cmd)

/*******************
 ** Define Struct **
 *******************/
struct st_susfs_sus_path {
	unsigned long           target_ino;
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
};

struct st_susfs_sus_mount {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned long           target_dev;
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
};

struct st_susfs_try_umount {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                     mnt_mode;
};

struct st_susfs_uname {
	char                    release[__NEW_UTS_LEN+1];
	char                    version[__NEW_UTS_LEN+1];
};

struct st_susfs_open_redirect {
	unsigned long           target_ino;
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	char                    redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
};

struct st_sus_su {
	int                     mode;
	char                    drv_path[256];
	int                     maj_dev_num;
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
		return 1;
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
	log(" usage: %s <CMD> [CMD options]\n", TAG);
	log("    <CMD>:\n");
	log("        add_sus_path </path/of/file_or_directory>\n");
	log("         |--> Added path and all its sub-paths will be hidden from several syscalls\n");
	log("         |--> Please be reminded that the target path must be added after the bind mount or overlay operation, otherwise it won't be effective\n");
	log("\n");
	log("        add_sus_mount <mounted_path>\n");
	log("         |--> Added mounted path will be hidden from /proc/self/[mounts|mountinfo|mountstats]\n");
	log("         |--> Please be reminded that the target path must be added after the bind mount or overlay operation, otherwise it won't be effective\n");
	log("\n");
	log("        add_sus_kstat_statically </path/of/file_or_directory> <ino> <dev> <nlink> <size>\\\n");
	log("                                 <atime> <atime_nsec> <mtime> <mtime_nsec> <ctime> <ctime_nsec>\n");
	log("                                 <blocks> <blksize>\n");
	log("         |--> Use 'stat' tool to find the format:\n");
	log("                  ino -> %%i, dev -> %%d, nlink -> %%h, atime -> %%X, mtime -> %%Y, ctime -> %%Z\n");
	log("                  size -> %%s, blocks -> %%b, blksize -> %%B\n");
	log("         |--> e.g., %s add_sus_kstat_statically '/system/addon.d' '1234' '1234' '2' '223344'\\\n", TAG);
	log("                       '1712592355' '0' '1712592355' '0' '1712592355' '0' '1712592355' '0'\\\n");
	log("                       '16' '512'\n");
	log("         |--> Or pass 'default' to use its original value:\n");
	log("         |--> e.g., %s add_sus_kstat_statically '/system/addon.d' 'default' 'default' 'default' 'default'\\\n", TAG);
	log("                       '1712592355' 'default' '1712592355' 'default' '1712592355' 'default'\\\n");
	log("                       'default' 'default'\n");
	log("\n");
	log("        add_sus_kstat </path/of/file_or_directory>\n");
	log("         |--> Add the desired path BEFORE it gets bind mounted or overlayed, this is used for storing original stat info in kernel memory\n");
	log("         |--> This command must be completed with <update_sus_kstat> later after the added path is bind mounted or overlayed\n");
	log("\n");
	log("        update_sus_kstat </path/of/file_or_directory>\n");
	log("         |--> Add the desired path you have added before via <add_sus_kstat> to complete the kstat spoofing procedure\n");
	log("         |--> This updates the target ino, but size and blocks are remained the same as current stat\n");
	log("\n");
	log("        update_sus_kstat_full_clone </path/of/file_or_directory>\n");
	log("         |--> Add the desired path you have added before via <add_sus_kstat> to complete the kstat spoofing procedure\n");
	log("         |--> This updates the target ino only, other stat members are remained the same as the original stat\n");
	log("\n");
	log("        add_try_umount </path/of/file_or_directory> <mode>\n");
	log("         |--> Added path will be umounted from KSU for all UIDs that are NOT su allowed, and profile template configured with umount\n");
	log("         |--> <mode>: 0 -> umount with no flags, 1 -> umount with MNT_DETACH\n");
	log("         |--> NOTE: susfs umount takes precedence of ksu umount\n");
	log("\n");
	log("        run_try_umount\n");
	log("         |--> Make all sus mounts to be private and umount them one by one in kernel for the mount namespace of current process\n");
	log("\n");
	log("        set_uname <release> <version>\n");
	log("         |--> NOTE: Only 'release' and <version> are spoofed as others are no longer needed\n");
	log("         |--> Spoof uname for all processes, set string to 'default' to imply the function to use original string\n");
	log("         |--> e.g., set_uname '4.9.337-g3291538446b7' 'default'\n");
	log("\n");
	log("        enable_log <0|1>\n");
	log("         |--> 0: disable susfs log in kernel, 1: enable susfs log in kernel\n");
	log("\n");
	log("        set_bootconfig </path/to/fake_bootconfig_file>\n");
	log("         |--> Spoof the output of /proc/bootconfig from a text file\n");
	log("\n");
	log("        add_open_redirect </target/path> </redirected/path>\n");
	log("         |--> Redirect the target path to be opened with user defined path\n");
	log("\n");
	log("        sus_su <0|1|2>\n");
	log("         |--> NOTE-1:\n");
	log("              - For mode 1: It disables kprobe hooks made by ksu, and instead,\n");
	log("                a sus_su character device driver with random name will be created, and user\n");
	log("                need to use a tool named 'sus_su' together with a path file in same current directory\n");
	log("                named '" SUS_SU_CONF_FILE_PATH "' to get a root shell from the sus_su driver.'\n");
	log("                ** sus_su userspace tool and an overlay mount is required **'\n");
	log("              - For mode 2: It disables kprobe hooks made by ksu, and instead,\n");
	log("                the non-kprobe inline hooks will be enbaled, just the same implementation for non-gki kernel without kprobe supported)\n");
	log("                ** Needs no extra userspace tools and mounts **\n");
	log("         |--> NOTE-2:\n");
	log("                Please see the service.sh template from ksu_module_susfs for the usage\n");
	log("         |--> 0: enable core ksu kprobe hooks and disable sus_su driver\n");
	log("         |--> 1: disable the core ksu kprobe hooks and enable sus_su fifo driver\n");
	log("         |--> 2: disable the core ksu kprobe hooks and enable sus_su just with non-kprobe hooks\n");
	log("\n");
}

/*******************
 ** Main Function **
 *******************/
int main(int argc, char *argv[]) {
	int error = -1;

	pre_check();
	// add_sus_path
	if (argc == 3 && !strcmp(argv[1], "add_sus_path")) {
		struct st_susfs_sus_path info = {0};
		struct stat sb;

		if (get_file_stat(argv[2], &sb)) {
			log("%s not found, skip adding its ino\n", info.target_pathname);
			return 1;
		}
		info.target_ino = sb.st_ino;
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_ADD_SUS_PATH, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_ADD_SUS_PATH);
		return error;
	// add_sus_mount
	} else if (argc == 3 && !strcmp(argv[1], "add_sus_mount")) {
		struct st_susfs_sus_mount info;
		struct stat sb;

		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		if (get_file_stat(argv[2], &sb)) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return 1;
		}
		info.target_dev = sb.st_dev;
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_ADD_SUS_MOUNT, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_ADD_SUS_MOUNT);
		return error;
	// add_sus_kstat_statically
	} else if (argc == 15 && !strcmp(argv[1], "add_sus_kstat_statically")) {
		struct st_susfs_sus_kstat info;
		struct stat sb;
		char* endptr;
		unsigned long ino, dev, nlink, size, atime, atime_nsec, mtime, mtime_nsec, ctime, ctime_nsec, blksize;
		long blocks;

		if (get_file_stat(argv[2], &sb)) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return 1;
		}
		
		info.is_statically = true;
		/* ino */
		if (strcmp(argv[3], "default")) {
			ino = strtoul(argv[3], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
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
				return 1;
			}
			sb.st_dev = dev;
		}
		/* nlink */
		if (strcmp(argv[5], "default")) {
			nlink = strtoul(argv[5], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_nlink = nlink;
		}
		/* size */
		if (strcmp(argv[6], "default")) {
			size = strtoul(argv[6], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_size = size;
		}
		/* atime */
		if (strcmp(argv[7], "default")) {
			atime = strtol(argv[7], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_atime = atime;
		}
		/* atime_nsec */
		if (strcmp(argv[8], "default")) {
			atime_nsec = strtoul(argv[8], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_atimensec = atime_nsec;
		}
		/* mtime */
		if (strcmp(argv[9], "default")) {
			mtime = strtol(argv[9], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_mtime = mtime;
		}
		/* mtime_nsec */
		if (strcmp(argv[10], "default")) {
			mtime_nsec = strtoul(argv[10], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_mtimensec = mtime_nsec;
		}
		/* ctime */
		if (strcmp(argv[11], "default")) {
			ctime = strtol(argv[11], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_ctime = ctime;
		}
		/* ctime_nsec */
		if (strcmp(argv[12], "default")) {
			ctime_nsec = strtoul(argv[12], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_ctimensec = ctime_nsec;
		}
		/* blocks */
		if (strcmp(argv[13], "default")) {
			blocks = strtoul(argv[13], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_blocks = blocks;
		}
		/* blksize */
		if (strcmp(argv[14], "default")) {
			blksize = strtoul(argv[14], &endptr, 10);
			if (*endptr != '\0') {
				print_help();
				return 1;
			}
			sb.st_blksize = blksize;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		copy_stat_to_sus_kstat(&info, &sb);
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY);
		return error;
	// add_sus_kstat
	} else if (argc == 3 && !strcmp(argv[1], "add_sus_kstat")) {
		struct st_susfs_sus_kstat info;
		struct stat sb;

		if (get_file_stat(argv[2], &sb)) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return 1;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.is_statically = false;
		info.target_ino = sb.st_ino;
		copy_stat_to_sus_kstat(&info, &sb);
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_ADD_SUS_KSTAT, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_ADD_SUS_KSTAT);
		return error;
	// update_sus_kstat
	} else if (argc == 3 && !strcmp(argv[1], "update_sus_kstat")) {
		struct st_susfs_sus_kstat info = {0};
		struct stat sb;

		if (get_file_stat(argv[2], &sb)) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return 1;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.is_statically = false;
		info.target_ino = sb.st_ino;
		info.spoofed_size = sb.st_size; // use the current size, not the spoofed one
		info.spoofed_blocks = sb.st_blocks; // use the current blocks, not the spoofed one
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_UPDATE_SUS_KSTAT, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_UPDATE_SUS_KSTAT);
		return error;
	// update_sus_kstat_full_clone
	} else if (argc == 3 && !strcmp(argv[1], "update_sus_kstat_full_clone")) {
		struct st_susfs_sus_kstat info = {0};
		struct stat sb;

		if (get_file_stat(argv[2], &sb)) {
			log("[-] Failed to get stat from path: '%s'\n", argv[2]);
			return 1;
		}
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		info.is_statically = false;
		info.target_ino = sb.st_ino;
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_UPDATE_SUS_KSTAT, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_UPDATE_SUS_KSTAT);
		return error;
	// add_try_umount
	} else if (argc == 4 && !strcmp(argv[1], "add_try_umount")) {
		struct st_susfs_try_umount info;
		char* endptr;
		char abs_path[PATH_MAX], *p_abs_path;
		
		strncpy(info.target_pathname, argv[2], SUSFS_MAX_LEN_PATHNAME-1);
		p_abs_path = realpath(info.target_pathname, abs_path);
		if (p_abs_path == NULL) {
			perror("realpath");
			return 1;
		}
		if (!strcmp(p_abs_path, "/system") ||
			!strcmp(p_abs_path, "/vendor") ||
			!strcmp(p_abs_path, "/product") ||
			!strcmp(p_abs_path, "/data/adb/modules") ||
			!strcmp(p_abs_path, "/debug_ramdisk") ||
			!strcmp(p_abs_path, "/sbin")) {
			log("[-] %s cannot be added to try_umount, because it will be umounted by ksu lastly\n", p_abs_path);
			return 1;
		}
		if (strcmp(argv[3], "0") && strcmp(argv[3], "1")) {
			print_help();
			return 1;
		}
		info.mnt_mode = strtol(argv[3], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return 1;
		}
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_ADD_TRY_UMOUNT, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_ADD_TRY_UMOUNT);
		return error;
	// run_try_umount
	} else if (argc == 2 && !strcmp(argv[1], "run_try_umount")) {
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS, NULL, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS);
		return error;
	// set_uname
	} else if (argc == 4 && !strcmp(argv[1], "set_uname")) {
		struct st_susfs_uname info;
		
		strncpy(info.release, argv[2], __NEW_UTS_LEN);
		strncpy(info.version, argv[3], __NEW_UTS_LEN);
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_SET_UNAME, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_SET_UNAME);
		return error;
	// enable_log
	} else if (argc == 3 && !strcmp(argv[1], "enable_log")) {
		if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
			print_help();
			return 1;
		}
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_ENABLE_LOG, atoi(argv[2]), NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_ENABLE_LOG);
		return error;
	// set_bootconfig
	} else if (argc == 3 && !strcmp(argv[1], "set_bootconfig")) {
		char abs_path[PATH_MAX], *p_abs_path, *buffer;
		FILE *file;
		long file_size;
		size_t result; 

		p_abs_path = realpath(argv[2], abs_path);
		if (p_abs_path == NULL) {
			perror("realpath");
			return 1;
		}
		file = fopen(abs_path, "rb");
		if (file == NULL) {
			perror("Error opening file");
			return 1;
		}
		fseek(file, 0, SEEK_END);
		file_size = ftell(file);
		rewind(file);
		buffer = (char *)malloc(sizeof(char) * (file_size + 1));
		if (buffer == NULL) {
			perror("No enough memory");
			fclose(file);
			return 1;
		}
		result = fread(buffer, 1, file_size, file);
		if (result != file_size) {
			perror("Reading error");
			fclose(file);
			free(buffer);
			return 1;
		}
		buffer[file_size] = '\0';
		fclose(file);
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_SET_BOOTCONFIG, buffer, NULL, &error);
		free(buffer);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_SET_BOOTCONFIG);
		return error;
	// add_open_redirect
	} else if (argc == 4 && !strcmp(argv[1], "add_open_redirect")) {
		struct st_susfs_open_redirect info;
		struct stat sb;
		char target_pathname[PATH_MAX], *p_abs_target_pathname;
		char redirected_pathname[PATH_MAX], *p_abs_redirected_pathname;

		p_abs_target_pathname = realpath(argv[2], target_pathname);
		if (p_abs_target_pathname == NULL) {
			perror("realpath");
			return 1;
		}
		strncpy(info.target_pathname, target_pathname, SUSFS_MAX_LEN_PATHNAME-1);
		p_abs_redirected_pathname = realpath(argv[3], redirected_pathname);
		if (p_abs_redirected_pathname == NULL) {
			perror("realpath");
			return 1;
		}
		strncpy(info.redirected_pathname, redirected_pathname, SUSFS_MAX_LEN_PATHNAME-1);
		if (get_file_stat(info.target_pathname, &sb)) {
			log("[-] Failed to get stat from path: '%s'\n", info.target_pathname);
			return 1;
		}
		info.target_ino = sb.st_ino;
		prctl(KERNEL_SU_OPTION, CMD_SUSFS_ADD_OPEN_REDIRECT, &info, NULL, &error);
		PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_ADD_OPEN_REDIRECT);
		return error;
	// sus_su
	} else if (argc == 3 && !strcmp(argv[1], "sus_su")) {
		struct st_sus_su info;
		dev_t dev;
		mode_t mode = 0666;
		FILE *f_path;

		if (strcmp(argv[2], "0") && strcmp(argv[2], "1") && strcmp(argv[2], "2")) {
			print_help();
			return error;
		}

		if (!strcmp(argv[2], "1")) {
			info.mode = SUS_SU_WITH_OVERLAY;
			info.maj_dev_num = -1;
			prctl(KERNEL_SU_OPTION, CMD_SUSFS_SUS_SU, &info, NULL, &error);
			PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_SUS_SU);
			if (error)
				return error;
			dev = makedev(info.maj_dev_num, 0);
			if (mknod(info.drv_path, S_IFCHR | mode, dev) < 0) {
				log("failed to mknod '%s'\n", info.drv_path);
				return 1;
			}
			log("[+] device node created at '%s'\n", info.drv_path);

			f_path = fopen(SUS_SU_CONF_FILE_PATH, "w");
			if (!f_path) {
				log("failed to fopen '%s'\n", info.drv_path);
				return 1;
			}
			
			fputs(info.drv_path, f_path);
			fclose(f_path);

			if (system("export DRV_PATH=`cat " SUS_SU_CONF_FILE_PATH "`; chmod 666 ${DRV_PATH} && chcon u:object_r:null_device:s0 ${DRV_PATH}")) {
				log("[-] failed to change permission for '%s'\n", info.drv_path);
				return 1;
			}
		} else if (!strcmp(argv[2], "2")) {
			info.mode = SUS_SU_WITH_HOOKS;
			info.maj_dev_num = -1;
			prctl(KERNEL_SU_OPTION, CMD_SUSFS_SUS_SU, &info, NULL, &error);
			PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_SUS_SU);
		} else if (!strcmp(argv[2], "0")) {
			info.mode = 0;
			prctl(KERNEL_SU_OPTION, CMD_SUSFS_SUS_SU, &info, NULL, &error);
			PRT_MSG_IF_OPERATION_NOT_SUPPORTED(error, CMD_SUSFS_SUS_SU);
			if (error)
				return error;
			if (system("export DRV_PATH=`cat " SUS_SU_CONF_FILE_PATH "`; rm -f ${DRV_PATH}")) {
				log("[-] failed to remove '%s'\n", info.drv_path);
				return error;
			} else {
				log("[+] '%s' is removed\n", info.drv_path);
			}
		}
		return error;
	} else {
		print_help();
	}
out:
	return 0;
}

