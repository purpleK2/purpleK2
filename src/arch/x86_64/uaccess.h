#ifndef UACCESS_H
#define UACCESS_H

#include <scheduler/scheduler.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define __user

#define USER_TOP USER_STACK_TOP

struct fault_ctx {
    void *resume_ip;
    int faulted;
};

static inline bool user_range_ok(const void *ptr, size_t n) {
    uintptr_t start = (uintptr_t)ptr;
    uintptr_t end   = start + n;

    if (end < start)            return false;
    if (start >= USER_TOP)      return false;
    if (end > USER_TOP)         return false;

    return true;
}

extern struct fault_ctx *current_fault_ctx;

size_t copy_from_user(void *dst, const void *user_src, size_t n);
size_t copy_to_user(void *user_dst, const void *src, size_t n);
size_t strncpy_from_user(char *dst, const char __user *user_src, size_t max_len);

#endif // UACCESS_H