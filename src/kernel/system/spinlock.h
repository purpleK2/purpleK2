#ifndef SPINLOCK_H
#define SPINLOCK_H 1

#include <stdatomic.h>
#include <stdint.h>

void spinlock_acquire(atomic_flag *lock);
void spinlock_force_acquire(atomic_flag *lock);
void spinlock_release(atomic_flag *lock);

#endif