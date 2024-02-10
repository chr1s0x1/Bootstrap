#include <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <bsm/audit.h>
#include <xpc/xpc.h>
#include <stdio.h>
#include "fishhook.h"
#include <spawn.h>
#include <limits.h>
#include <dirent.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <roothide.h>

#define PT_DETACH 11    /* stop tracing a process */
#define PT_ATTACHEXC 14 /* attach to running process with signal exception */
int ptrace(int request, pid_t pid, caddr_t addr, int data);

int posix_spawnattr_set_launch_type_np(posix_spawnattr_t *attr, uint8_t launch_type);

int (*orig_csops)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
int (*orig_csops_audittoken)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int (*orig_posix_spawn)(pid_t * __restrict pid, const char * __restrict path,
                        const posix_spawn_file_actions_t *file_actions,
                        const posix_spawnattr_t * __restrict attrp,
                        char *const argv[ __restrict], char *const envp[ __restrict]);

int (*orig_posix_spawnp)(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]);


int hooked_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int result = orig_csops(pid, ops, useraddr, usersize);
    if (result != 0) return result;
    if (ops == 0) { // CS_OPS_STATUS
        *((uint32_t *)useraddr) |= 0x4000000; // CS_PLATFORM_BINARY
    }
    return result;
}

int hooked_csops_audittoken(pid_t pid, unsigned int ops, void * useraddr, size_t usersize, audit_token_t * token) {
    int result = orig_csops_audittoken(pid, ops, useraddr, usersize, token);
    if (result != 0) return result;
    if (ops == 0) { // CS_OPS_STATUS
        *((uint32_t *)useraddr) |= 0x4000000; // CS_PLATFORM_BINARY
    }
    return result;
}

void change_launchtype(const posix_spawnattr_t *attrp, const char *restrict path) {
    const char *prefixes[] = {
        "/private/var",
        "/var",
        "/private/preboot"
    };

    if (__builtin_available(macOS 13.0, iOS 15.0, tvOS 16.0, watchOS 9.0, *)) {
        for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
            size_t prefix_len = strlen(prefixes[i]);
            if (strncmp(path, prefixes[i], prefix_len) == 0) {
                if (attrp != 0) {

                    posix_spawnattr_set_launch_type_np((posix_spawnattr_t *)attrp, 0); // needs ios 16.0 sdk
                }
                break;
            }
        }
    }
}


int hooked_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    change_launchtype(attrp, path);

        return orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
    }

int hooked_posix_spawnp(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, posix_spawnattr_t *attrp, char *const argv[restrict], char *const envp[restrict]) {
    change_launchtype(attrp, path);
    const char *springboardPath = "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
    const char *coolerSpringboard = jbroot("/var/mobile/BSTRPFiles/System/Library/CoreServices/SpringBoard.app/SpringBoard");

    if (!strncmp(path, springboardPath, strlen(springboardPath))) {
        posix_spawnattr_set_launch_type_np((posix_spawnattr_t *)attrp, 0);
        path = coolerSpringboard;
        return posix_spawnp(pid, path, file_actions, (posix_spawnattr_t *)attrp, argv, envp);
    }
            
    return orig_posix_spawnp(pid, path, file_actions, (posix_spawnattr_t *)attrp, argv, envp);
}

bool (*xpc_dictionary_get_bool_orig)(xpc_object_t dictionary, const char *key);
bool hook_xpc_dictionary_get_bool(xpc_object_t dictionary, const char *key) {
    if (!strcmp(key, "LogPerformanceStatistics")) return true;
    else return xpc_dictionary_get_bool_orig(dictionary, key);
}
    
    __attribute__((constructor)) static void start(int argc, char **argv) {
        printf("[LaunchHooker] we've been initialized!\n");
        int our_pid = getpid();
        if(our_pid == 1) {
            printf("[LaunchHooker]: we are pid: %d\n", getpid());
        }
        
        struct rebinding rebindings[] = (struct rebinding[]){
            {"csops", hooked_csops, (void *)&orig_csops},
            {"csops_audittoken", hooked_csops_audittoken, (void *)&orig_csops_audittoken},
            {"posix_spawn", hooked_posix_spawn, (void *)&orig_posix_spawn},
            {"posix_spawnp", hooked_posix_spawnp, (void *)&orig_posix_spawnp},
            {"xpc_dictionary_get_bool", hook_xpc_dictionary_get_bool, (void *)&xpc_dictionary_get_bool_orig},
        };
        rebind_symbols(rebindings, sizeof(rebindings)/sizeof(struct rebinding));
    }
