#ifndef VFS_H
#define VFS_H 1

#include <fs/file_io.h>
#include <fs/fsid.h>
#include "types.h"

#include <spinlock.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>

#define V_CREATE (1 << 0)
#define V_READ   (1 << 1)
#define V_WRITE  (1 << 2)
#define V_EXCL   (1 << 3)
#define V_TRUNC  (1 << 4)
#define V_DIR    (1 << 5)

// compiler skill issue
typedef struct vnode vnode_t;
typedef struct vfs vfs_t;

typedef struct vfs_fstype {
    uint16_t id;   // unique vfs type id
    char name[64]; // like "fat32" or "ext4"

    int (*mount)(void *device, char *mount_point, void *mount_data,
                 vfs_t **out);

    struct vfs_fstype *next;
} vfs_fstype_t;

typedef enum vnode_type {
    VNODE_NULL,
    VNODE_REGULAR,
    VNODE_DIR,
    VNODE_BLOCK,
    VNODE_CHAR,
    VNODE_LINK,
    VNODE_PIPE,
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

typedef struct dirent {
    uint64_t d_ino;
    uint64_t d_off;
    uint64_t d_reclen;
    uint8_t d_type;   // same as vnode_type
    char d_name[256]; // filename !!!
} dirent_t;

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
    int (*open)(vnode_t **, int, bool, fileio_t **);
    int (*close)(vnode_t *, int, bool);

    int (*read)(vnode_t *, size_t *, size_t *, void *);
    int (*write)(vnode_t *, void *, size_t *, size_t *);
    int (*ioctl)(vnode_t *, int, void *);
    int (*lookup)(vnode_t *, const char *, vnode_t **);
    int (*readdir)(vnode_t *, dirent_t *, size_t *);
    int (*readlink)(vnode_t *, char *, size_t);
    int (*mkdir)(vnode_t *, const char *, int);
    int (*rmdir)(vnode_t *, const char *);
    int (*create)(vnode_t *, const char *, int, vnode_t **);
    int (*remove)(vnode_t *, const char *);
    int (*symlink)(vnode_t *, const char *, const char *);
} vnops_t;

typedef struct vnode {
    // TODO: flags
    // TODO: Unix IPC , Stream (shrugs)
    // TODO: shared/exclusive locks

    char *path;
    vnode_type_t vtype;
    void *node_data; // FS-specific structure about the file

    uid_t uid;
    gid_t gid;
    mode_t mode;

    vnops_t *ops;

    vfs_t *vfs_here; // what vfs is mounted in this vnode
    vfs_t *root_vfs; // in what vfs this vnode resides

    uint32_t refcount;

    atomic_flag vnode_lock;
} vnode_t;

typedef struct vfs {
    // TODO: flags (i won't add them rn)
    // TODO: block size? (wth is that)
    vfs_fstype_t fs_type;
    vnode_t *root_vnode;
    void *vfs_data; // points to the FS-specific structure

    // for future :^)
    atomic_flag vfs_lock;

    vfsops_t *ops;

    struct vfs *next; // next VFS
} vfs_t;

extern vfs_t *vfs_list;

// driver api thingeth
int vfs_register_fstype(vfs_fstype_t *fstype);
int vfs_unregister_fstype(const char *name);
vfs_fstype_t *vfs_find_fstype(const char *name);

vfs_t *vfs_create(vfs_fstype_t *fs_type, void *fs_data);
vfs_t *vfs_mount(void *device, const char *fstype_name, char *path,
                 void *mount_data);
int vfs_unmount(const char *path);
int vfs_append(vfs_t *vfs);

vnode_t *vnode_create(vfs_t *root_vfs, char *path, vnode_type_t type,
                      void *data);
void vnode_ref(vnode_t *vnode);
void vnode_unref(vnode_t *vnode);

int vfs_resolve_mount(const char *path, vfs_t **out, char **remaining_path);
int vfs_lookup(const char *path, vnode_t **out);
int vfs_lookup_parent(const char *path, vnode_t **parent, char **filename);

int vfs_open(const char *path, int flags, fileio_t **out);
int vfs_read(vnode_t *vnode, size_t size, size_t offset, void *out);
int vfs_write(vnode_t *vnode, void *buf, size_t size, size_t offset);
int vfs_ioctl(vnode_t *vnode, int request, void *arg);
int vfs_close(vnode_t *vnode);

int vfs_readdir(vnode_t *vnode, dirent_t *entries, size_t *count);
int vfs_mkdir(const char *path, int mode);
int vfs_rmdir(const char *path);

int vfs_readlink(const char *path, char *buf, size_t size);
int vfs_symlink(const char *target, const char *linkpath);

#endif
