#include "user.h"
#include "scheduler/scheduler.h"

uid_t get_current_uid(void) {
    return (get_current_pcb() ? get_current_pcb()->cred->uid : UID_INVALID);
}