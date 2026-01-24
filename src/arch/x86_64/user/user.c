#include "user.h"
#include "scheduler/scheduler.h"

user_cred_t get_current_cred(void) {
    return (get_current_pcb() ? *(get_current_pcb()->cred) : (user_cred_t){UID_INVALID, UID_INVALID, UID_INVALID, UID_INVALID, UID_INVALID, UID_INVALID, {0}, 0});
}