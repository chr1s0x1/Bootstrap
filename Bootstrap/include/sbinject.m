//
//  sbinject.m
//  Bootstrap
//
//  Created by Chris Coding on 1/20/24.
//

#import <Foundation/Foundation.h>
#include "../bootstrap.h"
#include "sbinject.h"

int file_index;
kern_return_t kr;
bool setupyes;
bool isxpc = false;

struct proc proc_info = {0};
struct fileproc fileproc_info = {0};
// struct fglob fileglob_info; // <--- junk doesn't even work
// struct kfd kern_fd;
struct vnode vnode_info = {0};
struct namecache nc_info = {0};


// vnode functions and more

uint64_t unsign_kptr(uint64_t pac_kaddr) {
    if ((pac_kaddr & 0xFFFFFF0000000000) == 0xFFFFFF0000000000) {
        return pac_kaddr;
    }
    if(t1sz_boot != 0) {
        return pac_kaddr |= ~((1ULL << (64U - t1sz_boot)) - 1U);
    }
    return pac_kaddr;
}

uint64_t getProc(pid_t pid) {
    uint64_t proc = get_kernproc();
    printf("[+] kernproc: 0x%llx\n", proc);
    
    while (true) {
        if(kread32(proc + off_p_pid) == pid) {
            printf("[+] found proc: 0x%llx\n", proc);
            return proc;
        }
        proc = kread64(proc + off_p_list_le_prev);
        if(!proc) {
            return -1;
        }
    }
    printf("[-] getProc failed\n");
    return 0;
}

uint64_t getVnodeAtPath(char* filename) {
    printf("[+] getVnodeAtPath(%s)\n", filename);
    file_index = open(filename, O_RDONLY);
    if (file_index == -1) return -1;
    
    uint64_t proc = get_selfproc();
    if(!ADDRISVALID(proc)) proc = getProc(getpid());
    printf("[+] proc: 0x%llx\n", proc);
    kreadbuf(proc, &proc_info, sizeof(proc_info));
    uint64_t filedesc_pac = proc_info.p_fd_fd_ofiles;
    uint64_t filedesc = filedesc_pac | pac_mask;
    uint64_t openedfile = kread64(filedesc + (8 * file_index));
    kreadbuf(openedfile, &fileproc_info, sizeof(fileproc_info));
    uint64_t fileglob_pac = fileproc_info.fp_glob;
    uint64_t fileglob = fileglob_pac | pac_mask;
   // kreadbuf(fileglob, &fileglob_info, sizeof(fileglob));
    uint64_t vnode_pac = kread64(fileglob + off_fg_data);
    uint64_t vnode = vnode_pac | pac_mask;
    close(file_index);
    
    return vnode;
}

uint64_t getVnodeAtPathByChdir(char *path) {
    printf("[+] getVnodeAtPathByChdir(%s)\n", path);
    if(access(path, F_OK) == -1) {
        printf("access not OK\n");
        return -1;
    }
    if(chdir(path) == -1) {
        printf("chdir not OK\n");
        return -1;
    }
    
    u64 self = get_selfproc();
    kreadbuf(self, &proc_info, sizeof(proc_info));
    uint64_t fd_cdir_vp = kread64(self + proc_info.p_fd_fd_ofiles + off_fd_cdir);
    if(!ADDRISVALID(fd_cdir_vp)) {printf("[+] getVnodeAtPathByChdir: unable to get vnode\n");  return 0;}
    chdir("/");
    printf("[+] fd_cdir_vp: 0x%llx\n", fd_cdir_vp);
    return fd_cdir_vp;
}

/*
int inject_dylib_in_binary(NSString* dylibPath, NSString* binarypath) {
    
    NSFileManager* FM = [NSFileManager defaultManager];
    if(![FM fileExistsAtPath:dylibPath] || ![FM fileExistsAtPath:binarypath]) {
        STRAPLOG("[Dylib Inject] ERR: invalid path for dylib/binary");
        return -1;
    }
    
    STRAPLOG("[Dylib Inject] Injecting (%s) into (%s)", (dylibPath).UTF8String, binarypath.UTF8String);
    FILE* fp = fopen(binarypath.UTF8String, "r+");
    
    if(!fp) {
        STRAPLOG("[Dylib Inject] ERR: unable to read binary");
        fclose(fp);
        return -2;
    }
    
    fseeko(fp, 0, SEEK_END);
    off_t file_size = ftello(fp);
    rewind(fp);
    struct thin_header mh = {0};
    fseek(fp, 0, SEEK_SET);
    fread(&mh, sizeof(mh), 1, fp);

    NSMutableData* data = [[dylibPath dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    
    bool injected = insertLoadEntryIntoBinary(dylibPath, data, mh, LC_LOAD_DYLIB);
    if(!injected) {
        STRAPLOG("[Dylib Inject] ERR: unable to inject (%s) into (%s)!", dylibPath.UTF8String, binarypath.UTF8String);
        fclose(fp);
        return -3;
    }
    
    ftruncate(fileno(fp), file_size);
    
    STRAPLOG("[Dylib Inject] (%s) was injected into (%s) succesfully", dylibPath.UTF8String, binarypath.UTF8String);
    fclose(fp);
    return 0;
}


bool Setup_Injection(NSString* injectloc, NSString* newinjectloc, bool forxpc) {
    
    NSString* SpringBoardPath = @"/System/Library/CoreServices/SpringBoard.app";
    NSString* NewSBPath = jbroot(SpringBoardPath);
    int returnval;
    NSFileManager* FM = NSFileManager.defaultManager;
    NSError* errhandle;
    NSString* fastSignPath = [BootstrapAppPath() stringByAppendingPathComponent:@"basebin/fastPathSign"]; // may remove this
    NSString* ldidPath = [BootstrapAppPath() stringByAppendingPathComponent:@"basebin/ldid"];
    NSString* launchdents = [BootstrapAppPath() stringByAppendingPathComponent:@"basebin/launchdents.plist"];
    NSString* xpcents = [BootstrapAppPath()stringByAppendingPathComponent:@"basebin/xpcents.plist"];// need to modify file to have actual xpc ents
    NSString* sbents = [BootstrapAppPath() stringByAppendingPathComponent:@"include/libs/SBtools/SpringBoardEnts.plist"];
    NSString* SBreplaceBinary = [BootstrapAppPath() stringByAppendingPathComponent:@"include/libs/SBtools/SBTool"];
    
    STRAPLOG("[Setup Inject] setting up environment for SB Injection");
    
    if([FM fileExistsAtPath:newinjectloc] == 0) {
        STRAPLOG("[Setup Inject] NOTICE: (%s) already exists, we're gonna go ahead and resign then return..", newinjectloc.UTF8String);
        goto resign;
    }
    
    if(access(injectloc.UTF8String, F_OK) != 0) {
        STRAPLOG("[Setup Inject] ERR: we can't access %s", injectloc.UTF8String);
        return false;
    }
    
    // 1) copy over injectloc to boostrap location
    
    kr = [FM copyItemAtPath:injectloc toPath:newinjectloc error:&errhandle];
    if(kr != KERN_SUCCESS) {
        STRAPLOG("[Setup Inject] ERR: unable to copy xpc/launchd to path! error-string: (%s)", [[errhandle localizedDescription] UTF8String]);
        return false;
    }
    
    STRAPLOG("[Setup Inject] copied xpc/launchd binary at (%s)", newinjectloc.UTF8String);
    
    
resign:;
    
    // 2) Copy over SpringBoard.app to bootstrap path
    
    kr = [FM copyItemAtPath:SpringBoardPath toPath:jbroot(SpringBoardPath) error:&errhandle];
    if(kr != KERN_SUCCESS) {
        STRAPLOG("[Setup Inject] ERR: unable to copy SpringBoard to jbroot path, error-string: (%s)", [[errhandle localizedDescription] UTF8String]);
        goto setupfailed;
    }
    
    [FM removeItemAtPath:[NewSBPath stringByAppendingPathComponent:@"Springboard"] error:nil];
    assert(![FM fileExistsAtPath:[NewSBPath stringByAppendingPathComponent:@"SpringBoard"]]);
    kr = [FM copyItemAtPath:SBreplaceBinary toPath:[NewSBPath stringByAppendingPathComponent:@"SpringBoard"] error:&errhandle];
    if(kr != KERN_SUCCESS) {
        STRAPLOG("[Setup Inject] ERR: unable to replace SB binary with our own, error-string: (%s)", [[errhandle localizedDescription] UTF8String]);
        goto setupfailed;
    }
    
    // 3) Sign fake SpringBoard & fake launchd/xpc
    
    returnval = spawnRoot(ldidPath, @[@"-S", sbents, [NewSBPath stringByAppendingPathComponent:@"SpringBoard"]], nil, nil);
    if(returnval != 0) {
        STRAPLOG("[Setup Inject] ERR: unable to sign fake SpringBoard binary (%d)", returnval);
        goto setupfailed;
    }
    
    STRAPLOG("[Setup Inject] fake SpringBoard was been signed");
    
    // we're gonna sign them with the respective entitlements
    if(forxpc) {
        returnval = spawnRoot(ldidPath, @[@"-S", xpcents, newinjectloc], nil, nil);
    } else {
        returnval = spawnRoot(ldidPath, @[@"-S", launchdents, newinjectloc], nil, nil);
    }
    if(returnval != 0) {
        STRAPLOG("[Setup Inject] ERR: an issue occured signing (%s) - (%d)", newinjectloc.UTF8String, returnval);
        return false;
    }
    
    STRAPLOG("[Setup Inject] (%s) - was signed successfully", newinjectloc.UTF8String);
    
    // 4) inject dylibs into fake signed xpc/launchd + fake signed SpringBoard
    
    if(!forxpc) {
        returnval = inject_dylib_in_binary([BootstrapAppPath() stringByAppendingPathComponent:@"include/libs/launchdhooker.dylib"], newinjectloc);
        if(returnval != 0) {
            STRAPLOG("[Setup Inject] ERR: unable to inject launchdhooker into fake launchd (%d)", returnval);
            return false;
        }
    } else { // TODO: Gotta create the fake xpcproxy hooker
        returnval = inject_dylib_in_binary([BootstrapAppPath() stringByAppendingPathComponent:@"include/libs/xpchooker.dylib"], newinjectloc);
        if(returnval != 0) {
            STRAPLOG("[Setup Inject] ERR: unable to inject xpchooker into fake xpcproxy (%d)", returnval);
            return false;
        }
    }
    
    STRAPLOG("[Setup Inject] dylib has been injected into (%s) succesfully", injectloc.UTF8String);
    
    returnval = inject_dylib_in_binary([BootstrapAppPath() stringByAppendingPathComponent:@"include/libs/SBHooker.dylib"], [NewSBPath stringByAppendingPathComponent:@"SpringBoard"]);
    if(returnval != 0) {
        STRAPLOG("[Setup Inject] ERR: unable to inject SBHooker into fake SpringBoard (%d)", returnval);
        return false;
    }
    
    STRAPLOG("[Setup Inject] SBHooker has been injected into the fake SpringBoard, we're done here");
    return true;
    
setupfailed:;
  //  remove(newinjectloc.fileSystemRepresentation);
  //  remove(jbroot(NewSBPath).fileSystemRepresentation);
    return false;
}

*/

// Credit to wh1te4ever for vnode swapping - https://github.com/wh1te4ever/kfund/blob/972651c0b4c81098b844b29d17741cb445772c74/kfd/fun/vnode.m#L217

int enable_SBInjection(u64 kfd, int method) {
    
    STRAPLOG("[SB Injection] enabling SB Injection..");
    
    /* address variables */
    _offsets_init(); // initiate offsets - may not be needed now >:)
    init_krw(kfd);
    int fd;
    int fd2;
    struct vnode rootvnode = {0};
    struct vnode lcdfilevnode = {0};
    struct vnode flcdfilevnode = {0}; // fake
    struct vnode xpcfilevnode = {0};
    struct namecache nc = {0};
    struct kfd essential;
    u64 selfproc = 0;
    u64 launchvnode = 0;
    
    /* file handling & location variables */
    NSFileManager *FM = NSFileManager.defaultManager;
    NSString* Bootstrap_patchloc = [BootstrapAppPath() stringByAppendingPathComponent:@"BSTRPFiles"];
    NSString* xpc_origlocation = @"/usr/libexec/xpcproxy";
    NSString* xpc_new_location = [Bootstrap_patchloc stringByAppendingPathComponent:@"xpcproxy"];
    NSString* lcd_origlocation = @"/sbin/launchd";
    NSString* new_lcd_location = [Bootstrap_patchloc stringByAppendingPathComponent:@"launchd"];
    
    /*
     We're gonna comment this out since I would want the fakes to be signed upon a reboot to ensure no signing issues + reboot obviously reverts changes
    
     if([FM fileExistsAtPath:@(xpc_new_location)] || [FM fileExistsAtPath:@(new_lcd_location)]) {
        SYSLOG("[SB Injection] NOTICE: patched versions of xpc and/or launchd already exists");
        return true;
    }
*/
    
    
    
    /*
     
     --  ALL OF THIS WILL BE HANDLED IN THE ROOTHELPER NOW -- 
     
    if(![FM fileExistsAtPath:Bootstrap_patchloc isDirectory:YES]) {
        mkdir(Bootstrap_patchloc.UTF8String, 0775);
        if(![FM fileExistsAtPath:Bootstrap_patchloc isDirectory:YES]) {
            [FM createDirectoryAtPath:Bootstrap_patchloc withIntermediateDirectories:NO attributes:nil error:nil];
            if(![FM fileExistsAtPath:Bootstrap_patchloc isDirectory:YES]) {
                STRAPLOG("[SB Injection] ERR: unable to create patch path");
                return -1;
            }
        }
    }
    
   // setupyes = Setup_Injection(lcd_origlocation, new_lcd_location, method == 2 ? isxpc = true:false);
   if(method == 1) {
        setupyes = Setup_Injection(lcd_origlocation, new_lcd_location, isxpc);
    } else {
        isxpc = true;
        setupyes = Setup_Injection(xpc_origlocation, xpc_new_location, isxpc);
    }
    
    if(!setupyes) {
        STRAPLOG("[SB Injection] ERR: unable to setup injection environment");
        goto failure;
    }
    */
    
    if(isxpc) {
        goto xpc;
    }
    
    STRAPLOG("[SB Injection] executing launchd patch");
    
    launchvnode = getVnodeAtPath(lcd_origlocation.fileSystemRepresentation);
    if(!ADDRISVALID(launchvnode)) {
        STRAPLOG("[SB Injection] ERR: unable to get launchd vnode");
        goto failure;
    }
    
    if(running_IO == false && SYSTEM_VERSION_LESS_THAN(@"16.4") && SYSTEM_VERSION_EQUAL_TO(@"16.6")) { // running_IO = true = device on ios 15
        
    // setting up the u64 locations with structs
    STRAPLOG("[SB Injection] modifying namecache (iOS 16)");
    kreadbuf(launchvnode, &lcdfilevnode, sizeof(lcdfilevnode)) ;
    kwrite32(launchvnode+off_vnode_v_usecount, lcdfilevnode.v_usecount+1);
    u64 replace_lcd = getVnodeAtPath(new_lcd_location.fileSystemRepresentation);
    if(ADDRISVALID(replace_lcd)) {
        STRAPLOG("[SB Injection] ERR: Unable to get fake launchd vnode");
        goto failure;
    }
        
    kreadbuf(replace_lcd, &flcdfilevnode, sizeof(flcdfilevnode));
    kwrite32(replace_lcd+off_vnode_v_usecount, flcdfilevnode.v_usecount+1);
    
    STRAPLOG("[SB Injection] launchd: %11x, fake launchd: %11x", lcdfilevnode, flcdfilevnode);
        
    // 1) get launchd namecache
        
    u64 launchnc = kread64(launchvnode + off_vnode_v_ncchildren_tqh_first);
        if(launchnc == 0 || ADDRISVALID(launchnc)) {
            launchnc = (u64)flcdfilevnode.v_ncchildren.tqh_first;
            if(launchnc == 0 || !ADDRISVALID(launchnc)) {
                STRAPLOG("[SB Injection] ERR: unable to grab launchd namecache!");
                goto failure;
            }
        }
    kreadbuf(launchnc, &nc, sizeof(nc));
    if(strcmp(nc.nc_name, "launchd") != 0) {
        STRAPLOG("[SB Injection] ERR: We don't have the correct namecache!");
        goto failure;
    }
        
    // 2) find & replace launchd's node with the fakes
        
    u64 lcdncvp = (u64)nc.nc_vp;
    if(!ADDRISVALID(lcdncvp)) {
        lcdncvp = kread64(launchnc + off_namecache_nc_vp);
        if(ADDRISVALID(lcdncvp)) {
            STRAPLOG("[SB Injection] ERR: unable to grab launchd nc vnode");
            goto failure;
        }
    }
        
    STRAPLOG("[SB Injection] replacing namecache vnode pointer");
        
    kwrite64(lcdncvp, replace_lcd);
        
    STRAPLOG("[SB Injection] launched namecache node pointer replaced with fake vnode!");
    return 0;
 /*
resignL1:;
    SYSLOG("[SB Injection] signing launchd (iOS 16)");
    rebuildSignature(@(new_lcd_location));
    SYSLOG("[SB Injection] fake launchd has been signed! (iOS 16)");
    return true;
            */
    } else {
        STRAPLOG("[SB Injection] modifying namecache (iOS 16/15)");
        u64 sbinvnode = getVnodeAtPathByChdir("/sbin");
        if(!ADDRISVALID(sbinvnode)) {
            STRAPLOG("[SB Injection] ERR: unable to get sbin vnode!");
            goto failure;
        }
        
        STRAPLOG("[SB Injection] got sbin vnode %llx", sbinvnode);
        
        u64 fakelaunchd = getVnodeAtPathByChdir(new_lcd_location.fileSystemRepresentation);
        if(!ADDRISVALID(fakelaunchd)) {
            STRAPLOG("[SB Injection] ERR: unable to get fake launchd vnode");
            goto failure;
        }
        
        STRAPLOG("[SB Injection] got fake launchd vnode: %llx", fakelaunchd);
        kreadbuf(sbinvnode, &vnode_info, sizeof(vnode_info));
        u64 vp_nameptr = kread64(sbinvnode + off_vnode_v_name);
        if(!ADDRISVALID(vp_nameptr)) vp_nameptr = (u64)vnode_info.v_name;
        u64 vp_namecache = kread64(sbinvnode + off_vnode_v_ncchildren_tqh_first);
        if(!ADDRISVALID(vp_namecache)) vp_namecache = (u64)vnode_info.v_ncchildren.tqh_first;
        kreadbuf(vp_namecache, &nc_info, sizeof(nc_info));
        u64 vnode = 0;
        struct vnode vnode2 = {0};
        if(vp_namecache == 0)
           goto failure;
        
        while(1) {
            if(vp_namecache == 0)
                break;
            vnode = kread64(vp_namecache + off_namecache_nc_vp);
            if(!ADDRISVALID(vnode)) vnode = (u64)nc_info.nc_vp;
            if(vnode == 0)
                break;
            kreadbuf(vnode, &vnode2, sizeof(vnode2));
            vp_nameptr = kread64(vnode + off_vnode_v_name);
            if(!ADDRISVALID(vp_nameptr)) vp_nameptr = (u64)vnode2.v_name;
            
            char vp_name[256];
            kreadbuf(kread64(vp_namecache + 96), &vp_name, 256);
    //        printf("vp_name: %s\n", vp_name);
            
            if(strcmp(vp_name, "launchd") == 0)
            {
                uint32_t fakelcd_id = kread64(fakelaunchd + 116);
                uint64_t patient = kread64(vp_namecache + 80);        // vnode the name refers
                uint32_t patient_vid = kread64(vp_namecache + 64);    // name vnode id
                STRAPLOG("[SB Injection] patient: %llx vid:%llx -> %llx\n", patient, patient_vid, fakelcd_id);

                kwrite64(vp_namecache + 80, fakelaunchd);
                kwrite32(vp_namecache + 64, fakelcd_id);
                
                STRAPLOG("[SB Injection] launched namecache node pointer replaced with fake vnode!");
                return 0;
            }
            vp_namecache = kread64(vp_namecache + off_namecache_nc_child_tqe_prev);
            if(!ADDRISVALID(vp_namecache)) vp_namecache = (u64)nc_info.nc_child.tqe_prev;
        }
        STRAPLOG("[SB Injection] ERR: unable to patch launchd!");
        goto failure;
}

 /*
ios15:;
    SYSLOG("[SB Injection] changing NSExecutablePath (iOS 15)");
        
    return true;

resignL2:;
    SYSLOG("[SB Injection] signing launchd (iOS 15)");
    rebuildSignature(@(new_lcd_location));
    SYSLOG("[SB Injection] fake launchd has been signed! (iOS 15)");
    return true;
      */
        
xpc:; // xpc method *should* work on ios 15 & 16, we can use this for now-
        
    STRAPLOG("[SB Injection] executing xpcproxy patch");
        
    fd = open(xpc_origlocation.fileSystemRepresentation, O_RDONLY);
    if(fd == -1) {
        SYSLOG("ERR: Unable to open xpcproxy");
        goto failure;
    }
    STRAPLOG("fd returned: %d", fd);
        
    size_t xpcfile_size = lseek(fd, 0, SEEK_END);
    STRAPLOG("xpcfile_size: %llx", xpcfile_size);
    if(xpcfile_size <= 0 ) { goto failure; }
        
    /* Ensure fake xpcproxy exists before continuing */
    if(![FM fileExistsAtPath:xpc_new_location]) {
        STRAPLOG("ERR: Fake xpcproxy is not in the right location");
        goto failure;
    }
    fd2 = open(xpc_new_location.fileSystemRepresentation, O_RDONLY);
    if(fd2 == -1) {
        STRAPLOG("ERR: Unable to open fake xpcproxy");
        goto failure;
    }
    STRAPLOG("fd2 returned: %d", fd2);
    size_t xpcfake_size = lseek(fd2, 0, SEEK_END);
    STRAPLOG("xpcfile_size: %llx", xpcfile_size);
    if(xpcfake_size <= 0 ) { goto failure; }

    selfproc = essential.info.kernel.current_proc;
    if(!ADDRISVALID(selfproc)) {
        selfproc = getProc(getpid());
        if(!ADDRISVALID(selfproc)) {
            STRAPLOG("[SB Injection] ERR: unable to get self proc");
            goto failure;
        }
    }
    
    u64 filedesc_pac = kread64(selfproc + off_p_pfd);
    u64 filedesc = unsign_kptr(filedesc_pac);
    u64 xpcfile = kread64(filedesc + (8 * fd));
    u64 fglob_pac = kread64(xpcfile + off_fp_glob);
    u64 fglob = unsign_kptr(fglob_pac);
    u64 xpcvnode_pac = kread64(fglob + off_fg_data);
    u64 xpcvnode = unsign_kptr(xpcvnode_pac);
    
    kreadbuf(xpcvnode, &xpcfilevnode, sizeof(xpcfilevnode));
    
    u64 launchd_proc = getProc(1);
    u64 textvp_pac = kread64(launchd_proc + off_p_textvp);
    u64 textvp = unsign_kptr(textvp_pac);
    u64 sbin_vnode = unsign_kptr(kread64(textvp + off_vnode_v_parent));
    u64 root_vnode = unsign_kptr(kread64(sbin_vnode + off_vnode_v_parent));
    if(!ADDRISVALID(root_vnode)) {
        STRAPLOG("[SB Injection] ERR: unable to get rootvnode");
        goto failure;
    }
    
    kreadbuf(root_vnode, &rootvnode, sizeof(rootvnode));
    STRAPLOG("[SB Injection] got rootvnode at: %llx", root_vnode);
    
    u64 rootmount = (u64)rootvnode.v_mount;
    if(!ADDRISVALID(rootmount)) {
        u64 rootmount_pac = kread64(root_vnode + off_vnode_v_mount);
        rootmount = unsign_kptr(rootmount_pac);
    }
    
    assert(ADDRISVALID(rootmount));
    
    u32 rootflags = kread32(rootmount + off_mount_mnt_flag);
    kwrite32(rootmount + off_mount_mnt_flag, rootflags & ~MNT_RDONLY);
    kwrite32(fglob + off_fg_flag, FREAD | FWRITE);
    
    if(xpcfilevnode.v_writecount <= 0) {
        kwrite32((u32)xpcfilevnode.v_writecount, (u32)xpcfilevnode.v_writecount + 1); // dont trust this so i'ma do the offset method too lol
        
        u32 xpc_writecount = kread32(xpcvnode + off_vnode_v_writecount);
        kwrite32(xpcvnode + off_vnode_v_writecount, xpc_writecount + 1);
    }
    
    // map xpc & fakexpc then replace
    char* xpcmap = mmap(NULL, xpcfile_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(xpcmap == MAP_FAILED) {
        STRAPLOG("[SB Injection] ERR: unable to map xpcproxy");
        goto failure;
    }
    
    char* fakexpcmap = mmap(NULL, xpcfake_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    if(fakexpcmap == MAP_FAILED) {
        STRAPLOG("[SB Injection] ERR: unable to map fake xpcproxy");
        goto failure;
    }
    
    STRAPLOG("[SB Injection] xpcproxy & fake xpcproxy mapped");
    
    memcpy(fakexpcmap, xpcmap, xpcfile_size);
    kr = msync(fakexpcmap, xpcfake_size, MS_SYNC);
    if(kr != KERN_SUCCESS) {
        STRAPLOG("[SB Injection] ERR: syncing over the data to fake xpc failed");
        goto failure;
    }

    STRAPLOG("[SB Injection] msync returned: %d", (int)kr);
    
    // unmap and revert changes of fglob & rootvnode + close fd, fd2
    munmap(xpcmap, xpcfile_size);
    munmap(fakexpcmap, xpcfake_size);
    
    kwrite32(fglob + off_fg_flag, FREAD);
    kwrite32(rootmount + off_mount_mnt_flag, rootflags);
    
    close(fd);
    close(fd2);
    
    STRAPLOG("[SB Injection] xpcproxy has been patched!");
    return 0;
/*
resignX:;
        
    SYSLOG("[SB Injection] Signing xpcproxy");
    rebuildSignature(@(xpc_new_location));
        
    if(fd && fd2 != 0) {
        close(fd);
        close(fd2);
    }
    
    SYSLOG("[SB Injection] fake xpcproxy has been signed!");
 */
        
failure:;
    if(ADDRISVALID(rootmount)) {kwrite32(rootmount + off_mount_mnt_flag, rootflags);}
    if(fd != 0) close(fd);
    if(fd2 != 0) close(fd2);
    if(file_index != 0) close(file_index);
    if([FM fileExistsAtPath:Bootstrap_patchloc isDirectory:YES]) {
   //     remove(xpc_new_location.fileSystemRepresentation);
     //   remove(new_lcd_location.fileSystemRepresentation);
       // remove(Bootstrap_patchloc.fileSystemRepresentation);
    }
    return -1;
}
