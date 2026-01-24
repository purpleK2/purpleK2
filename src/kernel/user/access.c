#include "access.h"
#include "errors.h"
#include "user/user.h"

int vnode_permission(const user_cred_t *cred, const vnode_t *vnode, int mask) {
    if (!cred || !vnode) {
        return -ENULLPTR;
    }

    mode_t mode = vnode->mode;

    if (cred->euid == UID_ROOT) {
        if (mask & X_OK) {
            if (!(mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
                return -EACCES;
            }
            return 0;
        }
    }

    if (cred->euid == vnode->uid) {
        if ((mask & R_OK) && !(mode & S_IRUSR)) return -EACCES;
        if ((mask & W_OK) && !(mode & S_IWUSR)) return -EACCES;
        if ((mask & X_OK) && !(mode & S_IXUSR)) return -EACCES;
    }

    if (cred->egid == vnode->gid) {
        if ((mask & R_OK) && !(mode & S_IRGRP)) return -EACCES;
        if ((mask & W_OK) && !(mode & S_IWGRP)) return -EACCES;
        if ((mask & X_OK) && !(mode & S_IXGRP)) return -EACCES;
        return 0;
    }

    if ((mask & R_OK) && !(mode & S_IROTH)) return -EACCES;
    if ((mask & W_OK) && !(mode & S_IWOTH)) return -EACCES;
    if ((mask & X_OK) && !(mode & S_IXOTH)) return -EACCES;

    return 0;
}