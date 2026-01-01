#include "file_io.h"
#include "ipc/pipe.h"
#include <errors.h>
#include <fs/vfs/vfs.h>
#include <memory/heap/kheap.h>
#include <stdio.h>
#include <string.h>
#include <util/macro.h>

int f2vflags(int fio_flags) {
    int vflags = 0;
    if (fio_flags & (O_CREATE)) {
        vflags |= V_CREATE;
    }
    /*  just keep it commented for now
    if (fio_flags & (O_DIRECTORY)) {
        vflags |= V_DIR;
    }
    */
    return vflags;
}

fileio_t *fio_create() {
    fileio_t *fio = kmalloc(sizeof(fileio_t));
    memset(fio, 0, sizeof(fileio_t));
    return fio;
}

fileio_t *open(const char *path, int flags) {
    UNUSED(flags);
    
    fileio_t *f = NULL;
   
	int ret = vfs_open(path, f2vflags(flags), &f);
    if (ret != 0) {
		return (void *)(uintptr_t)-ret; // most hackey thing ever ffs
    }
    
    f->offset = 0;
    f->flags = flags |= f->flags;
    
    return f;
}

size_t read(fileio_t *file, size_t size, void *out) {
    if (!file) {
        return 0;
    }
    
    if (file->flags & PIPE_READ_END) {
        pipe_read(file, out, &size);
        return size;
    } else if (file->flags & PIPE_WRITE_END) {
        return 0;
    }
    
    if (!(file->flags & SPECIAL_FILE_TYPE_DEVICE)) {
        if (file->offset >= file->size) {
            return 0;
        }
        if (size > file->size) {
            size = (file->size - file->offset);
        }
    }
    
    int ret = vfs_read(((vnode_t *)file->private), size, file->offset, out);
    if (ret != 0) {
        return 0;
    }
    
    file->offset += size;
    return size;
}

int write(fileio_t *file, void *buf, size_t size) {
    vnode_t *vn = file->private;
    
    if (file->flags & PIPE_WRITE_END) {
        pipe_write(file, buf, &size);
        return EOK;
    } else if (file->flags & PIPE_READ_END) {
        return -EBADF;
    }
    
    size_t offset = file->offset;
    if (file->flags & O_APPEND) {
        offset += file->size;
    }
    
    if (vfs_write(vn, buf, size, offset) != 0) {
        return -EIO;
    }
    
    file->offset += size;
    return EOK;
}

int close(fileio_t *file) {
    vnode_t *vn = file->private;
    
    if (file->flags & PIPE_READ_END || file->flags & PIPE_WRITE_END) {
        pipe_close(file);
        return 0;
    }
    
    if (vfs_close(vn) != 0) {
        return -1;
    }
    
    kfree(file);
    return EOK;
}

size_t seek(fileio_t *file, size_t offset, fseek_t whence) {
    if (!file) {
        return -ENULLPTR;
    }
    
    switch (whence) {
    case SEEK_CUR:
        file->offset += offset;
        break;
    case SEEK_END:
        file->offset = (file->size + offset);
        break;
    case SEEK_SET:
        file->offset = offset;
        break;
    default:
        break;
    }
    
    return file->offset;
}

size_t fcntl(fileio_t *file, fcntl_cmd_t cmd, void *arg) {
    switch (cmd) {
    case F_GETFL:
        return file->flags;
    case F_SETFL:
        size_t flags = *(size_t *)arg;
        file->flags |= (flags & (O_APPEND));
        break;
    default:
        break;
    }
    
    return EOK;
}

static const char *vtype_to_str(vnode_type_t type) {
    switch (type) {
    case VNODE_DIR:      return "DIR ";
    case VNODE_REGULAR:  return "FILE";
    case VNODE_BLOCK:    return "BLK ";
    case VNODE_CHAR:     return "CHR ";
    case VNODE_LINK:     return "LINK";
    case VNODE_PIPE:     return "PIPE";
    case VNODE_SOCKET:   return "SOCK";
    default:             return "????";
    }
}

static void fs_list_internal(vnode_t *dir, int depth, int max_depth, int indent) {
    if (max_depth != -1 && depth > max_depth) {
        return;
    }
    
    if (!dir || dir->vtype != VNODE_DIR) {
        return;
    }
    
    dirent_t entries[256];
    size_t count = 256;
    
    int ret = vfs_readdir(dir, entries, &count);
    if (ret != EOK) {
        return;
    }
    
    for (size_t i = 0; i < count; i++) {
        for (int j = 0; j < indent; j++) {
            kprintf("  ");
        }
        
        const char *type_str = vtype_to_str(entries[i].d_type);
        
        if (entries[i].d_type == VNODE_DIR) {
            kprintf("|- [%s] %s/\n", type_str, entries[i].d_name);
        } else if (entries[i].d_type == VNODE_LINK) {
            size_t path_len = strlen(dir->path) + strlen(entries[i].d_name) + 2;
            char *full_path = kmalloc(path_len);
            snprintf(full_path, path_len, "%s/%s", dir->path, entries[i].d_name);
            
            char target[256];
			int ret = vfs_readlink(full_path, target, sizeof(target));
            if (ret == EOK) {
                kprintf("|- [%s] %s -> %s\n", type_str, entries[i].d_name, target);
            } else {
                kprintf("|- [%s] %s -> ??? (%d)\n", type_str, entries[i].d_name, ret);
            }
            
            kfree(full_path);
        } else {
            kprintf("|- [%s] %s\n", type_str, entries[i].d_name);
        }
        
        if (entries[i].d_type == VNODE_DIR) {
            if (strcmp(entries[i].d_name, ".") == 0 || strcmp(entries[i].d_name, "..") == 0) {
                continue;
            }
            
            size_t path_len = strlen(dir->path) + strlen(entries[i].d_name) + 2;
            char *child_path = kmalloc(path_len);
           	if (strcmp(dir->path, "/") == 0) {
    			snprintf(child_path, path_len, "/%s", entries[i].d_name);
			} else {
    			snprintf(child_path, path_len, "%s/%s", dir->path, entries[i].d_name);
			}

            vnode_t *child_vnode;
            if (vfs_lookup(child_path, &child_vnode) == EOK) {
                fs_list_internal(child_vnode, depth + 1, max_depth, indent + 1);
                vnode_unref(child_vnode);
            }
			kfree(child_path);
        }
    }
}

int fs_list(const char *path, int max_depth) {
    if (!path) {
        return -EINVAL;
    }
    
    vnode_t *vnode;
    int ret = vfs_lookup(path, &vnode);
    if (ret != EOK) {
        kprintf("Error: Cannot access '%s'\n", path);
        return ret;
    }
    
    if (vnode->vtype != VNODE_DIR) {
        kprintf("Error: '%s' is not a directory\n", path);
        vnode_unref(vnode);
        return -ENOTDIR;
    }
    
    kprintf("%s\n", path);
    fs_list_internal(vnode, 0, max_depth, 0);
    
    vnode_unref(vnode);
    return EOK;
}
