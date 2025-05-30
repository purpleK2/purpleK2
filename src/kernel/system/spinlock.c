#include "spinlock.h"

#include <stdio.h>
#include <types.h>

void spinlock_acquire(lock_t *lock) {
    unsigned int timeout = 1000000;

    while (atomic_flag_test_and_set(lock)) {
        if (--timeout == 0) {
            debugf_warn("Spinlock deadlock detected\n");
            spinlock_release(lock);
        }

        asm("pause");
    }
}

void spinlock_release(lock_t *lock) {
    atomic_flag_clear(lock);
}
