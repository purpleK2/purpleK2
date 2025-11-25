#include "types.h"
#ifndef SPINLOCK_H
#define SPINLOCK_H 1

#include <stdatomic.h>
#include <stdint.h>

void spinlock_acquire(lock_t *lock);
void spinlock_release(lock_t *lock);

#endif