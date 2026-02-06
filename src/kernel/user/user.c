#include "user.h"
#include "scheduler/scheduler.h"

static user_cred_t bootstrap_cred = {
    .uid = UID_ROOT,
    .euid = UID_ROOT,
    .suid = UID_ROOT,
    .gid = GID_ROOT,
    .egid = GID_ROOT,
    .sgid = GID_ROOT,
    .ngroups = 0
};

user_cred_t* get_current_cred(void) {
    return (get_current_pcb() ? get_current_pcb()->cred : &bootstrap_cred);
}