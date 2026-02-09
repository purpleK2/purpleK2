#include "sleep.h"
#include "errors.h"

#include <scheduler/scheduler.h>
#include <structures/waitqueue.h>
#include <system/time.h>

extern registers_t *get_syscall_context(void);

static waitqueue_t sleep_wq;

void sleep_init(void) {
    waitqueue_init(&sleep_wq);
}

void sleep_timer_check(void) {
    if (sleep_wq.count == 0)
        return;

    waitqueue_wake_expired(&sleep_wq, get_ticks());
}

int do_nanosleep(const timespec_t *req, timespec_t *rem) {
    (void)rem;

    if (!req)
        return -EINVAL;

    if (req->tv_nsec >= 1000000000ULL)
        return -EINVAL;

    tcb_t *me = get_current_tcb();
    if (!me)
        return -EFAULT;

    registers_t *ctx = get_syscall_context();
    if (!ctx)
        return -EFAULT;
    
    uint64_t ms = req->tv_sec * 1000 + req->tv_nsec / NS_PER_TICK;

    if (ms == 0 && (req->tv_sec > 0 || req->tv_nsec > 0))
        ms = 1;

    if (ms == 0)
        return 0;

    uint64_t now    = get_ticks();
    uint64_t target = now + ms;

    ctx->rax = 0;

    me->regs        = ctx;
    me->wakeup_tick = target;

    waitqueue_prepare_wait(&sleep_wq);
    yield(ctx);

    return 0;
}
