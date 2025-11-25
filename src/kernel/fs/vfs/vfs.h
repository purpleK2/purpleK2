#ifndef VFS_H
#define VFS_H

#include "structures/avltree.h"
#include "types.h"
#include <stdint.h>

// vfs errors
#define VENOENT 1
#define VEBUSY  2

typedef struct fs_vfs fs_vfs_t;
typedef struct fs_node fs_node_t;
typedef struct fs_mount fs_mount_t;
typedef struct fs_open_file fs_open_file_t;
typedef struct fs_node_ops fs_node_ops_t;
typedef struct fs_vfs_ops fs_vfs_ops_t;
typedef struct stat stat_t;

typedef enum {
    FS_DEV,
    FS_PROC,
    FS_TMP,
    FS_EXT,
    FS_CUSTOM
} fs_type;

typedef enum fs_node_type {
    VNON,
    VREG,
    VDIR,
    VBLK,
    VCHR,
    VLNK,
    VSOCK,
    VBAD
} fs_node_type;

typedef struct fs_node {
    char *name;
    char *prefix;

    int flags;
    lock_t lock;
    fs_node_type type;

    void *data;
    fs_node_ops_t *ops;

    fs_vfs_t *vfs;

    fs_node_t *parent;
    AVLTree *children;
    AVLTree *next;
} fs_node_t;

typedef struct fs_node_ops {
    int (*open)(fs_node_t *node, fs_open_file_t *file);
    int (*close)(fs_node_t *node, fs_open_file_t *file);
    int (*read)(fs_node_t *node, char *buf, size_t len, size_t offset);
    int (*write)(fs_node_t *node, const char *buf, size_t len, size_t offset);
    int (*seek)(fs_node_t *node, size_t offset, int whence);
    int (*ioctl)(fs_node_t *node, int request, void *arg);
    int (*stat)(fs_node_t *node, stat_t *st);
    int (*mmap)(fs_node_t *node, size_t offset, size_t len, int prot,
                int flags);
    int (*poll)(fs_node_t *node, int events, void *arg);
    int (*fcntl)(fs_node_t *node, int cmd, void *arg);
    int (*lookup)(fs_node_t *dir, const char *name, fs_node_t **out);
    int (*mkdir)(fs_node_t *dir, const char *name, int flags);
    int (*unlink)(fs_node_t *dir, const char *name);
    int (*rename)(fs_node_t *old_dir, const char *old_name, fs_node_t *new_dir,
                  const char *new_name);
} fs_node_ops_t;

typedef struct fs_vfs_ops {
    int (*mount)(fs_vfs_t *vfs, fs_mount_t *mount);
    int (*unmount)(fs_vfs_t *vfs, fs_mount_t *mount);
    int (*statfs)(fs_vfs_t *vfs, stat_t *st);
    int (*sync)(fs_vfs_t *vfs);
    int (*create)(fs_vfs_t *vfs, fs_node_t *node, const char *name,
                  fs_node_type type, int flags);
    int (*remove)(fs_vfs_t *vfs, fs_node_t *node);
    int (*rename)(fs_vfs_t *vfs, fs_node_t *old_node, fs_node_t *new_node);
} fs_vfs_ops_t;

typedef struct fs_vfs {
    fs_type type;
    lock_t lock;

    fs_node_t *root;

    void *data;
    fs_vfs_ops_t *ops;
} fs_vfs_t;

typedef struct fs_mount {
    fs_vfs_t *vfs;
    fs_node_t *node;

    char *path;
    char *prefix;

    int flags;
    lock_t lock;

    void *data;
} fs_mount_t;

typedef struct fs_open_file {
    fs_node_t *node;
    void *data;

    size_t offset;
    size_t len;

    int mode;
    int flags;
} fs_open_file_t;

typedef struct stat {
    uint64_t st_size;  // File size in bytes
    uint32_t st_mode;  // File mode (permissions)
    uint32_t st_uid;   // User ID of owner
    uint32_t st_gid;   // Group ID of owner
    uint64_t st_ino;   // Inode number
    uint64_t st_dev;   // Device ID
    uint64_t st_rdev;  // Device ID (if special file)
    uint64_t st_atime; // Last access time
    uint64_t st_mtime; // Last modification time
    uint64_t st_ctime; // Last status change time
} stat_t;

// Core VFS functions
int vfs_register(fs_vfs_t *vfs);
int vfs_unregister(fs_vfs_t *vfs);
int vfs_mount(const char *path, fs_vfs_t *vfs, int flags);
int vfs_unmount(const char *path);
int vfs_lookup(const char *path, fs_node_t **out);
int vfs_open(const char *path, int flags, fs_open_file_t **out);
int vfs_close(fs_open_file_t *file);
int vfs_read(fs_open_file_t *file, void *buf, size_t len);
int vfs_write(fs_open_file_t *file, const void *buf, size_t len);
int vfs_seek(fs_open_file_t *file, size_t offset, int whence);
int vfs_stat(const char *path, stat_t *st);
int vfs_mkdir(const char *path, int flags);
int vfs_unlink(const char *path);
int vfs_rename(const char *oldpath, const char *newpath);
int vfs_sync(void);
int vfs_create(const char *path, fs_node_type type, int flags);
fs_node_t *vfs_root(void);

#endif // VFS_H
