#ifndef SPINLOCK_H
#define SPINLOCK_H 1

#include <stdatomic.h>
#include <stdint.h>
#include <types.h>

void spinlock_acquire(lock_t *lock);
void spinlock_force_acquire(lock_t *lock);

void spinlock_release(lock_t *lock);

#endif