//
//  sbinject.h
//  Bootstrap
//
//  Created by Chris Coding on 1/20/24.
//

#ifndef sbinject_h
#define sbinject_h

#include "libkfd.h"
#include "krw.h"
#include "utils.h"

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.41.9/bsd/sys/mount.h#L293
#define MNT_RDONLY      0x00000001      /* read only filesystem */
#define MNT_NOSUID      0x00000008      /* don't honor setuid bits on fs */
#define MNT_ROOTFS      0x00004000      /* identifies the root filesystem */
#define MNT_UPDATE      0x00010000      /* not a real mount, just an update */
//https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.41.9/bsd/sys/vnode_internal.h#L297
#define VISSHADOW       0x008000        /* vnode is a shadow file */

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.41.9/bsd/sys/fcntl.h#L112
//https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.41.9/bsd/sys/fcntl.h#L231
#define FREAD           0x00000001
#define FWRITE          0x00000002

struct  namecache {
    TAILQ_ENTRY(namecache)  nc_entry;       /* chain of all entries */
    TAILQ_ENTRY(namecache)  nc_child;       /* chain of ncp's that are children of a vp */
    union {
        LIST_ENTRY(namecache)  nc_link; /* chain of ncp's that 'name' a vp */
        TAILQ_ENTRY(namecache) nc_negentry; /* chain of ncp's that 'name' a vp */
    } nc_un;
    LIST_ENTRY(namecache)   nc_hash;        /* hash chain */
    vnode_t                 nc_dvp;         /* vnode of parent of name */
    vnode_t                 nc_vp;          /* vnode the name refers to */
    unsigned int            nc_hashval;     /* hashval of stringname */
    const char              *nc_name;       /* pointer to segment name in string cache */
};

#define XNU_PTRAUTH_SIGNED_PTR(x)

typedef struct {
    union {
        uint64_t lck_mtx_data;
        uint64_t lck_mtx_tag;
    };
    union {
        struct {
            uint16_t lck_mtx_waiters;
            uint8_t lck_mtx_pri;
            uint8_t lck_mtx_type;
        };
        struct {
            struct _lck_mtx_ext_ *lck_mtx_ptr;
        };
    };
} lck_mtx_t;

LIST_HEAD(buflists, buf);
typedef struct vnode* vnode_t;
typedef uint32_t kauth_action_t;
typedef struct vnode_resolve* vnode_resolve_t;

struct vnode {
    lck_mtx_t v_lock;                       /* vnode mutex */
    TAILQ_ENTRY(vnode) v_freelist;//****          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;//****         /* vnodes for mount point */
    TAILQ_HEAD(, namecache) v_ncchildren;//****   /* name cache entries that regard us as their parent */
    LIST_HEAD(, namecache) v_nclinks;//****       /* name cache entries that name this vnode */
    vnode_t  v_defer_reclaimlist;           /* in case we have to defer the reclaim to avoid recursion */
    uint32_t v_listflag;                    /* flags protected by the vnode_list_lock (see below) */
    uint32_t v_flag;                        /* vnode flags (see below) */
    uint16_t v_lflag; //devfs+VNAMED_FSHASH                       /* vnode local and named ref flags */
    uint8_t  v_iterblkflags;                /* buf iterator flags */
    uint8_t  v_references;                  /* number of times io_count has been granted */
    int32_t  v_kusecount;//****                   /* count of in-kernel refs */
    int32_t  v_usecount;//****                    /* reference count of users */
    int32_t  v_iocount;                     /* iocounters */
    void *   XNU_PTRAUTH_SIGNED_PTR("vnode.v_owner") v_owner; /* act that owns the vnode */
    uint16_t v_type;                        /* vnode type */
    uint16_t v_tag;                         /* type of underlying data */
    uint32_t v_id;                          /* identity of vnode contents */
    union {
        struct mount    * XNU_PTRAUTH_SIGNED_PTR("vnode.v_data") vu_mountedhere;  /* ptr to mounted vfs (VDIR) */
        struct socket   * XNU_PTRAUTH_SIGNED_PTR("vnode.vu_socket") vu_socket;     /* unix ipc (VSOCK) */
        struct specinfo * XNU_PTRAUTH_SIGNED_PTR("vnode.vu_specinfo") vu_specinfo;   /* device (VCHR, VBLK) */
        struct fifoinfo * XNU_PTRAUTH_SIGNED_PTR("vnode.vu_fifoinfo") vu_fifoinfo;   /* fifo (VFIFO) */
        struct ubc_info * XNU_PTRAUTH_SIGNED_PTR("vnode.vu_ubcinfo") vu_ubcinfo;    /* valid for (VREG) */
    } v_un;
    struct  buflists v_cleanblkhd;          /* clean blocklist head */
    struct  buflists v_dirtyblkhd;          /* dirty blocklist head */
    struct klist v_knotes;                  /* knotes attached to this vnode */
    /*
     * the following 4 fields are protected
     * by the name_cache_lock held in
     * excluive mode
     */
    kauth_cred_t    XNU_PTRAUTH_SIGNED_PTR("vnode.v_cred") v_cred; /* last authorized credential */
    kauth_action_t  v_authorized_actions;   /* current authorized actions for v_cred */
    int             v_cred_timestamp;       /* determine if entry is stale for MNTK_AUTH_OPAQUE */
    int             v_nc_generation;        /* changes when nodes are removed from the name cache */
    /*
     * back to the vnode lock for protection
     */
    int32_t         v_numoutput;                    /* num of writes in progress */
    int32_t         v_writecount;                   /* reference count of writers */
    const char *v_name;                     /* name component of the vnode */
    vnode_t XNU_PTRAUTH_SIGNED_PTR("vnode.v_parent") v_parent;//****??                       /* pointer to parent vnode */
    struct lockf    *v_lockf;               /* advisory lock list head */
    int(**v_op)(void *);                    /* vnode operations vector */
    mount_t XNU_PTRAUTH_SIGNED_PTR("vnode.v_mount") v_mount;                        /* ptr to vfs we are in */
    void *  v_data;                         /* private data for fs */
//#if CONFIG_MACF
    struct label *v_label;                  /* MAC security label */
//#endif
//#if CONFIG_TRIGGERS
    vnode_resolve_t v_resolve;              /* trigger vnode resolve info (VDIR only) */
//#endif /* CONFIG_TRIGGERS */
#if CONFIG_FIRMLINKS
    vnode_t v_fmlink;                       /* firmlink if set (VDIR only), Points to source
                                             *  if VFLINKTARGET is set, if  VFLINKTARGET is not
                                             *  set, points to target */
#endif /* CONFIG_FIRMLINKS */
#if CONFIG_IO_COMPRESSION_STATS
    io_compression_stats_t io_compression_stats;            /* IO compression statistics */
#endif /* CONFIG_IO_COMPRESSION_STATS */

#if CONFIG_IOCOUNT_TRACE
    vnode_iocount_trace_t v_iocount_trace;
#endif /* CONFIG_IOCOUNT_TRACE */

uint64_t unknown;
};

int enable_SBInjection(u64 kfd,int method);
#endif /* jbtools_h */
