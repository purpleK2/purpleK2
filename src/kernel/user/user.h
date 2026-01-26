#ifndef USER_H
#define USER_H

#include "types.h"
#include "user/group.h"

#include <stdint.h>

#define UID_INVALID ((uid_t)-1)
#define UID_ROOT 0

typedef struct user_cred {
    uid_t uid;
    uid_t euid;
    uid_t suid;

    gid_t gid;
    gid_t egid;
    gid_t sgid;

    gid_t groups[MAX_GROUPS];
    uint8_t ngroups;    
} user_cred_t;

user_cred_t* get_current_cred(void);

static inline int in_group(const struct user_cred *cred, gid_t gid) {
    if (cred->egid == gid)
        return 1;

    for (uint8_t i = 0; i < cred->ngroups; i++) {
        if (cred->groups[i] == gid)
            return 1;
    }
    return 0;
}

/* A process may change IDs only to its real, effective or saved ID OR if it is privileged */
static inline int is_privileged(void) {
    return get_current_cred()->euid == 0;
}

#endif // USER_H