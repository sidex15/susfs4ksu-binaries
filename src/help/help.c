/*
 * help.c - usage output. print_help() renders the top-level command list,
 * gated by the detected kernel version/ABI; print_more_help() renders the
 * per-command detailed help.
 */

#include <stdio.h>
#include <string.h>

#include "susfs.h"

void print_help(void) {
    printf("usage: %s <CMD> [CMD options]\n", TAG);
    printf("help: %s --help <CMD>  (for more details of a specific command)\n", TAG);
    if (g_abi != ABI_UNKNOWN)
        printf("  Detected kernel: susfs %s (ABI: %s)\n",
               g_version_string,
               g_abi == ABI_v2000 ? "sys_reboot" : "prctl");
    printf("\n  <CMD>:\n");
    printf("    add_sus_path </path>\n");
    if (HAVE(1510) || have_susfs_feature("CONFIG_KSU_SUSFS_SUS_PATH"))
        printf("    add_sus_path_loop </path>\n");
    if (HAVE(158) || !HAVE(2100)) {
        printf("    set_android_data_root_path </path/to/Android/data>\n");
        printf("    set_sdcard_root_path </path/to/sdcard>\n");
    }
    if (HAVE(2000)) {
        printf("    add_sus_mount <mounted_path> (If CLI feature is supported)\n");
    }
    else {
        printf("    add_sus_mount <mounted_path>\n");
    }
    if ((HAVE(158) || have_susfs_feature("CONFIG_KSU_SUSFS_SUS_MOUNT")) && g_abi == ABI_PRCTL)
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
    if (!HAVE(154))
        printf("    set_bootconfig </path/to/file>\n");
    if (HAVE(154))
        printf("    set_cmdline_or_bootconfig </path/to/file>\n");
    printf("    add_open_redirect </target> </redirect>\n");
    if (HAVE(1512))
        printf("    add_sus_map </path/to/library>\n");
    if (have_susfs_feature("CONFIG_KSU_SUSFS_SUS_MEMFD"))
        printf("    add_sus_memfd <memfd_name>\n");
    if (HAVE(1510))
        printf("    enable_avc_log_spoofing <0|1>\n");
    if (HAVE(153))
        printf("    show <version|enabled_features|variant>\n");
    if (g_abi == ABI_PRCTL)
        printf("    sus_su <0|2|show_working_mode>\n");
    printf("\n");
}

int print_more_help(const char *cmd) {
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
        if (HAVE(2100)) {
            printf("    add_open_redirect </target/path> </redirected/path> <uid_scheme>\n");
            printf("      |--> Redirect the target path to be opened with user defined path and pre-defined uid scheme\n");
            printf("      |--> <uid_scheme>\n");
            printf("           |--> 0: Effective for non-app processes (uid < 10000)\n");
            printf("           |--> 1: Effective for non-su processes of which uid is 0 (All root process but not with su domain)\n");
            printf("           |--> 2: Effective for non-su processes (Use it carefully!)\n");
            printf("           |--> 3: Effective for processes that are marked umounted with uid >= 10000 (Use it carefully!)\n");
            printf("           |--> 4: Effective for processes that are marked umounted (include most of the init spawned process, use it carefully!)\n");
            printf("      * Important Notes *\n");
            printf("      - Both target_pathname and redirected_pathname must be existed before they can be added to open_redirect\n");
            printf("      - Users have to take care of the selinux permission of both target_pathname and redirected_pathname by themselves\n");
            printf("      - Only effective for current process that matches the pre-defined uid scheme\n");
        }
        else {
            printf("    add_open_redirect </target/path> </redirected/path>\n");
            printf("      |--> Redirect the target path to be opened with user defined path\n");
            printf("      * Important Notes *\n");
            printf("      - Only effective for current process with uid <= 2000 or uid <= 11000 (for modified susfs kernels)\n");
        }
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
    if (strcmp(cmd, "add_sus_memfd") == 0) {
        printf("    add_sus_memfd <memfd_name>\n");
        printf("     |--> NOTE: This feature will be effective on all process\n");
        printf("     |--> NOTE: Remeber to prepend 'memfd:' to <memfd_name>\n");
        printf("     |--> e.g., add_sus_memfd 'memfd:/jit-cache'\n");
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
