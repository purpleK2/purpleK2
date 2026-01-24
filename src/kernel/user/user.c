#include "user.h"
#include "scheduler/scheduler.h"

user_cred_t* get_current_cred(void) {
    return (get_current_pcb() ? get_current_pcb()->cred : NULL);
}