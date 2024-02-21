//
//  main.m
//  Bootstrap
//
//  Created by Chris Coding on 2/21/24.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <spawn.h>
#import <objc/runtime.h>
#include <sys/syslog.h>


#import "codesign.h"
#import "coretrust_bug.h"
#import <choma/FAT.h>
#import <choma/MachO.h>
#import <choma/FileStream.h>
#import <choma/Host.h>
#import "TSUtil.h"
#import "optool/operations.h"

#import <SpringBoardServices/SpringBoardServices.h>

#define SYSLOG(fmt, ...) do { fmt[0];\
openlog("bootstrap",LOG_PID,LOG_AUTH);\
syslog(LOG_DEBUG, fmt, ## __VA_ARGS__);\
closelog();\
} while(0)

#define STRAPLOG(fmt, ...) do { fmt[0];\
SYSLOG(fmt, ## __VA_ARGS__);\
fprintf(stdout, [NSString stringWithFormat:@fmt, ## __VA_ARGS__].UTF8String);\
fprintf("[ROOT-HELPER]", stdout, "\n");\
fflush(stdout);\
} while(0)

#define JB_ROOT_PREFIX ".jbroot-"
#define JB_RAND_LENGTH  (sizeof(uint64_t)*sizeof(char)*2)

kern_return_t kr;

int is_jbrand_value(uint64_t value)
{
   uint8_t check = value>>8 ^ value >> 16 ^ value>>24 ^ value>>32 ^ value>>40 ^ value>>48 ^ value>>56;
   return check == (uint8_t)value;
}

int is_jbroot_name(const char* name)
{
    if(strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
        return 0;
    
    if(strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
        return 0;
    
    char* endp=NULL;
    uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
    if(!endp || *endp!='\0')
        return 0;
    
    if(!is_jbrand_value(value))
        return 0;
    
    return 1;
}

uint64_t resolve_jbrand_value(const char* name)
{
    if(strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
        return 0;
    
    if(strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
        return 0;
    
    char* endp=NULL;
    uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
    if(!endp || *endp!='\0')
        return 0;
    
    if(!is_jbrand_value(value))
        return 0;
    
    return value;
}

NSString* find_jbroot()
{
    //jbroot path may change when re-randomize it
    NSString * jbroot = nil;
    NSArray *subItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/Application/" error:nil];
    for (NSString *subItem in subItems) {
        if (is_jbroot_name(subItem.UTF8String))
        {
            NSString* path = [@"/var/containers/Bundle/Application/" stringByAppendingPathComponent:subItem];
            jbroot = path;
            break;
        }
    }
    return jbroot;
}

NSString *jbroot(NSString *path)
{
    NSString* jbroot = find_jbroot();
    return [jbroot stringByAppendingPathComponent:path];
}

NSString* BootStrapPath()
{
    NSError* mcmError;
    MCMAppContainer* appContainer = [MCMAppContainer containerWithIdentifier:@"com.roothide.Bootstrap-g3n3sis" createIfNecessary:NO existed:NULL error:&mcmError];
    if(!appContainer) return nil;
    return appContainer.url.path;
}

NSString* BootstrapappPath()
{
    return [BootStrapPath() stringByAppendingPathComponent:@"Bootstrap-G.app"];
}

int runLdid(NSArray* args, NSString** output, NSString** errorOutput)
{
    NSString* ldidPath = [BootstrapappPath() stringByAppendingPathComponent:@"basebin/ldid"];
    NSMutableArray* argsM = args.mutableCopy ?: [NSMutableArray new];
    [argsM insertObject:ldidPath.lastPathComponent atIndex:0];

    NSUInteger argCount = [argsM count];
    char **argsC = (char **)malloc((argCount + 1) * sizeof(char*));

    for (NSUInteger i = 0; i < argCount; i++)
    {
        argsC[i] = strdup([[argsM objectAtIndex:i] UTF8String]);
    }
    argsC[argCount] = NULL;

    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);

    int outErr[2];
    pipe(outErr);
    posix_spawn_file_actions_adddup2(&action, outErr[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&action, outErr[0]);

    int out[2];
    pipe(out);
    posix_spawn_file_actions_adddup2(&action, out[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&action, out[0]);
    
    pid_t task_pid;
    int status = -200;
    int spawnError = posix_spawn(&task_pid, [ldidPath fileSystemRepresentation], &action, NULL, (char* const*)argsC, NULL);
    for (NSUInteger i = 0; i < argCount; i++)
    {
        free(argsC[i]);
    }
    free(argsC);

    if(spawnError != 0)
    {
//        NSLog(@"posix_spawn error %d\n", spawnError);
        return spawnError;
    }

    do
    {
        if (waitpid(task_pid, &status, 0) != -1) {
            //printf("Child status %dn", WEXITSTATUS(status));
        } else
        {
            perror("waitpid");
            return -222;
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    close(outErr[1]);
    close(out[1]);

    NSString* ldidOutput = getNSStringFromFile(out[0]);
    if(output)
    {
        *output = ldidOutput;
    }

    NSString* ldidErrorOutput = getNSStringFromFile(outErr[0]);
    if(errorOutput)
    {
        *errorOutput = ldidErrorOutput;
    }

    return WEXITSTATUS(status);
}

int signAdhoc(NSString *filePath, NSString *entitlements) // lets just assume ldid is included ok
{
//        if(!isLdidInstalled()) return 173;

//        NSString *entitlementsPath = nil;
        NSString *signArg = @"-S";
        NSString* errorOutput;
        if(entitlements) {
//            NSData *entitlementsXML = [NSPropertyListSerialization dataWithPropertyList:entitlements format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
//            if (entitlementsXML) {
//                entitlementsPath = [[NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString] stringByAppendingPathExtension:@"plist"];
//                [entitlementsXML writeToFile:entitlementsPath atomically:NO];
                signArg = [signArg stringByAppendingString:entitlements];
//                signArg = [signArg stringByAppendingString:@" -Cadhoc"];
//                signArg = [signArg stringByAppendingString:@" -M"];
//                signArg = [signArg stringByAppendingString:@"/sbin/launchd"];
//            }
        }
        NSLog(@"roothelper: running ldid\n");
        int ldidRet = runLdid(@[signArg, filePath], nil, &errorOutput);
//        if (entitlementsPath) {
//            [[NSFileManager defaultManager] removeItemAtPath:entitlementsPath error:nil];
//        }

//        NSLog(@"roothelper: ldid exited with status %d", ldidRet);
//
//        NSLog(@"roothelper: - ldid error output start -");
//
//        printMultilineNSString(signArg);
//        printMultilineNSString(errorOutput);
//
//        NSLog(@"roothelper: - ldid error output end -");

        if(ldidRet == 0)
        {
            return 0;
        }
        else
        {
            return 175;
        }
    //}
}

int inject_dylib_in_binary(NSString* dylibPath, NSString* binarypath) {
    
    NSFileManager* FM = [NSFileManager defaultManager];
    if(![FM fileExistsAtPath:dylibPath] || ![FM fileExistsAtPath:binarypath]) {
        printf("[ROOT-HELPER][Dylib Inject] ERR: invalid path for dylib/binary\n");
        return -1;
    }
    
    printf("[Dylib Inject] Injecting (%s) into (%s)\n", (dylibPath).UTF8String, binarypath.UTF8String);
    FILE* fp = fopen(binarypath.UTF8String, "r+");
    
    if(!fp) {
        printf("[Dylib Inject] ERR: unable to read binary\n");
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
        printf("[Dylib Inject] ERR: unable to inject (%s) into (%s)!\n", dylibPath.UTF8String, binarypath.UTF8String);
        fclose(fp);
        return -3;
    }
    
    ftruncate(fileno(fp), file_size);
    
    printf("[Dylib Inject] (%s) was injected into (%s) succesfully\n", dylibPath.UTF8String, binarypath.UTF8String);
    fclose(fp);
    return 0;
}


bool Setup_Injection(NSString* injectloc, NSString* newinjectloc, bool forxpc) {
    
    NSString* log=nil;
    NSString* err=nil;
    
    NSString* SpringBoardPath = @"/System/Library/CoreServices/SpringBoard.app";
    NSString* NewSBPath = jbroot(SpringBoardPath);
    int returnval;
    NSFileManager* FM = NSFileManager.defaultManager;
    NSError* errhandle;
    NSString* fastSignPath = [BootstrapappPath() stringByAppendingPathComponent:@"basebin/fastPathSign"]; // may remove this
    NSString* ldidPath = [BootstrapappPath() stringByAppendingPathComponent:@"basebin/ldid"];
    NSString* launchdents = [BootstrapappPath() stringByAppendingPathComponent:@"basebin/launchdents.plist"];
    NSString* xpcents = [BootstrapappPath() stringByAppendingPathComponent:@"basebin/xpcents.plist"];// need to modify file to have actual xpc ents
    NSString* sbents = [BootstrapappPath() stringByAppendingPathComponent:@"include/libs/SBtools/SpringBoardEnts.plist"];
    NSString* SBreplaceBinary = [BootstrapappPath() stringByAppendingPathComponent:@"include/libs/SBtools/SBTool"];
    
    printf("[Setup Inject] setting up environment for SB Injection\n");
    
    if([FM fileExistsAtPath:newinjectloc] == 0) {
        printf("[Setup Inject] NOTICE: (%s) already exists, we're gonna go ahead and resign then return..\n", newinjectloc.UTF8String);
        goto resign;
    }
    
    if(access(injectloc.UTF8String, F_OK) != 0) {
        printf("[Setup Inject] ERR: we can't access %s\n", injectloc.UTF8String);
        return false;
    }
    
    // 1) copy over injectloc to boostrap location
    
    kr = [FM copyItemAtPath:injectloc toPath:newinjectloc error:&errhandle];
    if(kr != KERN_SUCCESS) {
        printf("[Setup Inject] ERR: unable to copy xpc/launchd to path! error-string: (%s)\n", [[errhandle localizedDescription] UTF8String]);
        return false;
    }
    
    printf("[Setup Inject] copied xpc/launchd binary at (%s\n)", newinjectloc.UTF8String);
    
    
resign:;
    
    // 2) Copy over SpringBoard.app to bootstrap path
    
    kr = [FM copyItemAtPath:SpringBoardPath toPath:jbroot(SpringBoardPath) error:&errhandle];
    if(kr != KERN_SUCCESS) {
        printf("[Setup Inject] ERR: unable to copy SpringBoard to jbroot path, error-string: (%s)\n", [[errhandle localizedDescription] UTF8String]);
        goto setupfailed;
    }
    
    [FM removeItemAtPath:[NewSBPath stringByAppendingPathComponent:@"Springboard"] error:nil];
    assert(![FM fileExistsAtPath:[NewSBPath stringByAppendingPathComponent:@"SpringBoard"]]);
    kr = [FM copyItemAtPath:SBreplaceBinary toPath:[NewSBPath stringByAppendingPathComponent:@"SpringBoard"] error:&errhandle];
    if(kr != KERN_SUCCESS) {
        printf("[Setup Inject] ERR: unable to replace SB binary with our own, error-string: (%s)\n", [[errhandle localizedDescription] UTF8String]);
        goto setupfailed;
    }
    
    // 3) Sign fake SpringBoard & fake launchd/xpc
    
    returnval = spawnRoot(ldidPath, @[@"-S", sbents, [NewSBPath stringByAppendingPathComponent:@"SpringBoard"]], nil, nil);
    if(returnval != 0) {
        printf("[Setup Inject] ERR: unable to sign fake SpringBoard binary (%d)\n", returnval);
        goto setupfailed;
    }
    
    printf("[Setup Inject] fake SpringBoard was been signed\n");
    
    // we're gonna sign them with the respective entitlements & fastpathsign
    if(forxpc) {
        returnval = signAdhoc(newinjectloc, xpcents); // spawnRoot(ldidPath, @[@"-S", xpcents, newinjectloc], nil, nil);
    } else {
        returnval = signAdhoc(newinjectloc, launchdents); // spawnRoot(ldidPath, @[@"-S", launchdents, newinjectloc], nil, nil);
    }
    if(returnval != 0) {
        printf("[Setup Inject] ERR: an issue occured signing (%s) - (%d)\n", newinjectloc.UTF8String, returnval);
        return false;
    }
    
    returnval = spawnRoot(fastSignPath, @[@"-i", newinjectloc, @"-r", @"-o", newinjectloc], &log, &err);
    if(returnval != 0) {
        printf("[Setup Inject] ERR: an issues occured fastpath signing (%s): \n\n %s \n\n %s\n", newinjectloc.UTF8String, log.UTF8String, err.UTF8String);
        return false;
    }
    
    printf("[Setup Inject] (%s) - was signed successfully\n", newinjectloc.UTF8String);
    
    // 4) inject dylibs into fake signed xpc/launchd + fake signed SpringBoard
    
    if(!forxpc) {
        returnval = inject_dylib_in_binary([BootstrapappPath() stringByAppendingPathComponent:@"include/libs/launchdhooker.dylib"], newinjectloc);
        if(returnval != 0) {
            printf("[Setup Inject] ERR: unable to inject launchdhooker into fake launchd (%d)\n", returnval);
            return false;
        }
    } else { // TODO: Gotta create the fake xpcproxy hooker
        returnval = inject_dylib_in_binary([BootstrapappPath() stringByAppendingPathComponent:@"include/libs/xpchooker.dylib"], newinjectloc);
        if(returnval != 0) {
            printf("[Setup Inject] ERR: unable to inject xpchooker into fake xpcproxy (%d)\n", returnval);
            return false;
        }
    }
    
    printf("[Setup Inject] dylib has been injected into (%s) succesfully", injectloc.UTF8String);
    
    returnval = inject_dylib_in_binary([BootstrapappPath() stringByAppendingPathComponent:@"include/libs/SBHooker.dylib"], [NewSBPath stringByAppendingPathComponent:@"SpringBoard"]);
    if(returnval != 0) {
        printf("[Setup Inject] ERR: unable to inject SBHooker into fake SpringBoard (%d)\n", returnval);
        return false;
    }
    
    printf("[Setup Inject] SBHooker has been injected into the fake SpringBoard, we're done here\n");
    return true;
    
setupfailed:;
  // remove(newinjectloc.fileSystemRepresentation);
  // remove(jbroot(NewSBPath).fileSystemRepresentation);
    return false;
}

int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
        
        printf("[ROOT-HELPER] RootHelper called! initiating..\n");
        
        NSFileManager *fm = [NSFileManager defaultManager];
        BOOL directory = YES;
        loadMCMFramework();
        
        NSString* action = [NSString stringWithUTF8String:argv[1]];
        NSString* method = [NSString stringWithUTF8String:argv[2]];
        
        bool doxpc = strcmp(method.UTF8String, "launchd") == 0 ? true:false;
        
        if([action isEqual:@"install"]) {
            
            NSString* Bootstrap_patchloc = [BootstrapappPath() stringByAppendingString:@"BSTRPFiles"];
            NSString* xpc_origlocation = @"/usr/libexec/xpcproxy";
            NSString* xpc_new_location = jbroot(@"xpcproxy");
            
            NSString* lcd_origlocation = @"/sbin/launchd";
            NSString* new_lcd_location = jbroot(@"launchd");
            
            mkdir(Bootstrap_patchloc.UTF8String, 0775);
            if(![fm fileExistsAtPath:Bootstrap_patchloc isDirectory:&directory]) {
                [fm createDirectoryAtPath:Bootstrap_patchloc withIntermediateDirectories:NO attributes:nil error:nil];
                if(![fm fileExistsAtPath:Bootstrap_patchloc isDirectory:&directory]) {
                    printf("[ROOT-HELPER] ERR: unable to create strap folder!\n");
                    exit(-1);
                }
            }

            printf("[ROOT-HELPER] Strap folder created\n");
            bool setup;
            if(doxpc) {
                setup = Setup_Injection(xpc_origlocation, xpc_new_location, doxpc);
            } else {
                setup = Setup_Injection(lcd_origlocation, new_lcd_location, doxpc);
            }
            if(!setup) {
                printf("[ROOT-HELPER] ERR: SpringBoard setup failed!\n");
                exit(-2);
            }
            
            printf("[ROOT-HELPER] SpringBoard setup complete, we're done here!\n");
            exit(0);
            
        } else if ([action isEqual:@"uninstall"]) {
            printf("[ROOT-HELPER] Uninstalling..");
            if(doxpc) {
                remove(jbroot(@"xpcproxy").UTF8String);
            } else {
                remove(jbroot(@"launchd").UTF8String);
            }
            
            [fm removeItemAtPath:jbroot(@"/System/Library/CoreServices/SpringBoard.app") error:nil];
            remove(jbroot(@"/System/Library/CoreServices/SpringBoard.app/").UTF8String); // ensure that it's removed
            
            printf("[ROOT-HELPER] Everything uninstalled\n");
            exit(0);
        }
        
        
        }
    }
