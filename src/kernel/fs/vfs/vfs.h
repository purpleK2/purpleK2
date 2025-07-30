#ifndef VFS_H
#define VFS_H 1

#include <fs/fsid.h>

#include <spinlock.h>

#include <stdbool.h>
#include <stddef.h>

// compiler skill issue
typedef struct vnode vnode_t;
typedef struct vfs vfs_t;

typedef enum vfs_fstype {
    VFS_UNIMPLEMENTED, // this should always be the first one
    VFS_RAMFS,
    VFS_ISO9660,
    VFS_FAT32,
    VFS_EXT, // TODO: maybe one for each version?
} vfs_fstype_t;

typedef enum vnode_type {
    VNODE_NULL,
    VNODE_REGULAR,
    VNODE_DIR,
    VNODE_BLOCK,
    VNODE_LINK,
    VNODE_SOCKET,
    VNODE_BAD,
} vnode_type_t;

typedef struct statfs {
    fsid_t fsid;

    uint64_t block_size;
    uint64_t total_blocks;
    uint64_t free_blocks;

    uint64_t total_nodes;
    uint64_t free_nodes;

} statfs_t;

typedef struct fid {
    size_t fid_len; /* length of data */
    char *fid_data; /* variable size */
} fid_t;

typedef struct vfs_ops {
    int (*mount)(vfs_t *, char *, void *);
    int (*unmount)(vfs_t *);

    int (*root)(vfs_t *, vnode_t **);

    int (*statfs)(vfs_t *, statfs_t *);

    int (*sync)(vfs_t *);

    int (*fid)(vfs_t *, vnode_t *, fid_t **);
    int (*vget)(vfs_t *, vnode_t **, fid_t *);
} vfsops_t;

typedef struct vnode_ops {
    int (*open)(vnode_t **, int, bool);
    int (*close)(vnode_t *, int, bool);

    int (*read)(vnode_t *, size_t, size_t, void *);
    int (*write)(vnode_t *, void *, size_t, size_t);
    // TODO: the rest of the operations
} vnops_t;

typedef struct vnode {
    // TODO: flags
    // TODO: Unix IPC , Stream (shrugs)
    // TODO: shared/exclusive locks

    char *path;
    vnode_type_t vtype;
    void *node_data; // FS-specific structure about the file

    vnops_t *ops;

    vfs_t *vfs_here; // what vfs is mounted in this vnode
    vfs_t *root_vfs; // in what vfs this vnode resides
} vnode_t;

typedef struct vfs {
    // TODO: flags (i won't add them rn)
    // TODO: block size? (wth is that)
    vfs_fstype_t fs_type;
    vnode_t *root_vnode;
    void *vfs_data; // points to the FS-specific structure

    // for future :^)
    lock_t vfs_lock;

    vfsops_t *ops;

    struct vfs *next; // next VFS
} vfs_t;

// struct for open files (something like FILE*)

vfs_t *vfs_create(vfs_fstype_t fs_type, void *fs_data);
int vfs_mount(vfs_t *vfs, char *path, void *rootvn_data);

int vfs_append(vfs_t *vfs);
vnode_t *vnode_create(char *path, void *data);

int vfs_open(vfs_t *vfs, char *path, int flags, vnode_t **out);
int vfs_read(vnode_t *vnode, size_t size, size_t offset, void *out);
int vfs_write(vnode_t *vnode, void *buf, size_t size, size_t offset);
int vfs_close(vnode_t *vnode);

#endif