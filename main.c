/*
 * main.c - ksu_susfs universal userspace tool: argument parsing and dispatch.
 *
 * All command logic lives in the src/ modules; see include/susfs.h for the
 * shared declarations and the runtime version-detection strategy.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "susfs.h"

int main(int argc, char *argv[]) {
    pre_check();
    detect_susfs_version();
    load_sus_path_layout_cache();

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
        if (!HAVE(158) || HAVE(2100)) { printf("[-] Requires susfs v1.5.8-v2.0.0\n"); return 1; }
        return cmd_set_external_dir(argv[2], CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH);
    }

    if (!strcmp(cmd, "set_sdcard_root_path") && argc == 3) {
        if (!HAVE(158) || HAVE(2100)) { printf("[-] Requires susfs v1.5.8-v2.0.0\n"); return 1; }
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
        if (!HAVE(159) || HAVE(2100)) { printf("[-] Requires susfs v1.5.9-v2.0.0\n"); return 1; }
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

    // For v1.5.x - v2.0.0
    if (!strcmp(cmd, "add_open_redirect") && argc == 4 && !HAVE(2100))
        return cmd_add_open_redirect(argv[2], argv[3]);
    // For v2.1.0+
    if (!strcmp(cmd, "add_open_redirect") && argc == 5 && HAVE(2100))
        return cmd_add_open_redirect_2100(argv[2], argv[3], argv[4]);

    if (!strcmp(cmd, "add_sus_map") && argc == 3) {
        if (!HAVE(1512)) { printf("[-] Requires susfs v1.5.12+\n"); return 1; }
        return cmd_add_sus_map(argv[2]);
    }

    if (!strcmp(cmd, "add_sus_memfd") && argc == 3) {
        if (!have_susfs_feature("CONFIG_KSU_SUSFS_SUS_MEMFD")){
            printf("[-] Requires CONFIG_KSU_SUSFS_SUS_MEMFD kernel feature\n");
            return 1;
        }
        return cmd_add_sus_memfd(argv[2]);
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
