#ifndef WAITQUEUE_H
#define WAITQUEUE_H 1

#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>

#include <scheduler/scheduler.h>
#include <memory/heap/kheap.h>

typedef struct wq_entry {
    tcb_t            *thread;
    struct wq_entry  *next;
} wq_entry_t;

typedef struct waitqueue {
    wq_entry_t  *head;
    wq_entry_t  *tail;
    size_t       count;
    atomic_flag  lock;
} waitqueue_t;

static inline void waitqueue_init(waitqueue_t *wq) {
    wq->head  = NULL;
    wq->tail  = NULL;
    wq->count = 0;
    wq->lock  = (atomic_flag)ATOMIC_FLAG_INIT;
}

static inline void waitqueue_prepare_wait(waitqueue_t *wq) {
    tcb_t *me = get_current_tcb();
    if (!me) return;

    if (me->state == THREAD_WAITING)
        return;

    wq_entry_t *entry = kmalloc(sizeof(wq_entry_t));
    if (!entry) return;

    entry->thread = me;
    entry->next   = NULL;

    spinlock_acquire(&wq->lock);

    if (wq->tail) {
        wq->tail->next = entry;
    } else {
        wq->head = entry;
    }
    wq->tail = entry;
    wq->count++;

    me->state = THREAD_WAITING;

    spinlock_release(&wq->lock);
}

static inline void waitqueue_sleep(waitqueue_t *wq) {
    waitqueue_prepare_wait(wq);

    yield(get_current_tcb()->regs);
}

static inline bool waitqueue_wake_one(waitqueue_t *wq) {
    spinlock_acquire(&wq->lock);

    wq_entry_t *entry = wq->head;
    if (!entry) {
        spinlock_release(&wq->lock);
        return false;
    }

    wq->head = entry->next;
    if (!wq->head)
        wq->tail = NULL;
    wq->count--;

    tcb_t *thread = entry->thread;
    thread->state = THREAD_READY;

    spinlock_release(&wq->lock);

    scheduler_enqueue(thread);

    kfree(entry);
    return true;
}

static inline size_t waitqueue_wake_all(waitqueue_t *wq) {
    spinlock_acquire(&wq->lock);

    size_t woken = 0;
    wq_entry_t *entry = wq->head;
    while (entry) {
        wq_entry_t *next = entry->next;
        entry->thread->state = THREAD_READY;
        scheduler_enqueue(entry->thread);
        kfree(entry);
        woken++;
        entry = next;
    }

    wq->head  = NULL;
    wq->tail  = NULL;
    wq->count = 0;

    spinlock_release(&wq->lock);
    return woken;
}

#endif // WAITQUEUE_H
