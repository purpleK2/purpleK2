#ifndef ACCESS_H
#define ACCESS_H

#include "fs/vfs/vfs.h"
#include "user/user.h"
#define R_OK 0x4
#define W_OK 0x2
#define X_OK 0x1

#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100

#define S_IRGRP 0040
#define S_IWGRP 0020
#define S_IXGRP 0010

#define S_IROTH 0004
#define S_IWOTH 0002
#define S_IXOTH 0001

#define	S_IFDIR	 0040000	/* Directory.  */
#define	S_IFCHR	 0020000	/* Character device.  */
#define	S_IFBLK	 0060000	/* Block device.  */
#define	S_IFREG	 0100000	/* Regular file.  */
#define	S_IFIFO	 0010000	/* FIFO.  */
#define	S_IFLNK	 0120000	/* Symbolic link.  */
#define	S_IFSOCK 0140000	/* Socket.  */

int vnode_permission(const user_cred_t *cred, const vnode_t *vnode, int mask);
bool is_in_group(const user_cred_t *cred, gid_t gid);

#endif // ACCESS_H