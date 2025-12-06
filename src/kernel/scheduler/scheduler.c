#include "scheduler.h"

#include <gdt/gdt.h>

#include <cpu.h>
#include <errors.h>
#include <kernel.h>
#include <string.h>

#include <memory/heap/kheap.h>
#include <memory/pmm/pmm.h>
#include <memory/vmm/vflags.h>
#include <memory/vmm/vmm.h>
#include <paging/paging.h>

#include <smp/smp.h>

#include <stdio.h>

#include <fs/procfs/procfs.h>

static cpu_queue_t *thread_queues;
static tcb_t **current_threads;
static int cpu_count;

procfs_t *procfs;

atomic_flag SCHEDULER_LOCK = ATOMIC_FLAG_INIT;

// SHOULD BE CALLED **ONLY ONCE** IN KSTART. NOWHERE ELSE.
int init_scheduler() {
    cpu_count = get_bootloader_data()->cpu_count;

    thread_queues   = kmalloc(sizeof(cpu_queue_t) * cpu_count);
    current_threads = kmalloc(sizeof(tcb_t *) * cpu_count);
    memset(thread_queues, 0, sizeof(cpu_queue_t) * cpu_count);
    memset(current_threads, 0, sizeof(tcb_t *) * cpu_count);

    // create the procFS
    procfs = procfs_create();
    procfs_vfs_init(procfs, SCHEDULER_PROCFS_MOUNT);
    return 0;
}

static tcb_t *pick_next_thread(int cpu) {
    tcb_t *thread = thread_queues[cpu].head;

    for (; thread != NULL; thread = thread->next) {
        if (thread->state == THREAD_READY) {
            return thread;
        }
    }

    return NULL;
}

// I WANT ALL OF THE BITS :speaking_head: :fire: :fire:
static uint64_t global_pid = 0;

// @param name name of the process (it's optional)
int proc_create(void (*entry)(), int flags, char *name) {
    pcb_t *proc = kmalloc(sizeof(pcb_t));
    memset(proc, 0, sizeof(pcb_t));
    proc->pid   = __sync_fetch_and_add(&global_pid, 1);
    proc->state = PROC_READY;

    if (name) {
        proc->name = strdup(name);
    }

    proc->fds      = NULL;
    proc->fd_count = 0;

    // Enhanced VMM context creation with proper permissions
    int vflags = (flags & TF_MODE_USER ? VMO_USER_RW : VMO_KERNEL_RW);
    if (flags & TF_MODE_USER) {
        process_vmm_init(&proc->vmc, vflags);
    } else {
        proc->vmc = get_kernel_vmc();
    }

    proc->cwd = NULL;

    debugf_debug("Created process PID=%d flags=0x%x mode=%s\n", proc->pid,
                 flags, (flags & TF_MODE_USER) ? "USER" : "KERNEL");

    thread_create(proc, entry, flags);

    procfs_pcb_t *procfs_proc =
        procfs_proc_create(proc); // automatically creates the threads inside
    procfs_proc_append(procfs, procfs_proc);

    return proc->pid;
}

int thread_create(pcb_t *parent, void (*entry)(), int flags) {
    tcb_t *thread = kmalloc(sizeof(tcb_t));
    memset(thread, 0, sizeof(tcb_t));
    thread->tid        = __sync_fetch_and_add(&parent->thread_count, 1);
    thread->flags      = flags;
    thread->state      = THREAD_READY;
    thread->parent     = parent;
    thread->time_slice = SCHEDULER_THREAD_TS;

    thread->fpu = (void *)PHYS_TO_VIRTUAL(pmm_alloc_page());
    memset(thread->fpu, 0, 512);

    registers_t *ctx = kmalloc(sizeof(registers_t));
    memset(ctx, 0, sizeof(registers_t));

    if (flags & TF_MODE_USER) {

        thread->kernel_stack =
            (void *)PHYS_TO_VIRTUAL(pmm_alloc_pages(SCHEDULER_STACK_PAGES));
        thread->user_stack =
            (void *)PHYS_TO_VIRTUAL(pmm_alloc_pages(SCHEDULER_STACK_PAGES));

        uint64_t user_stack_top  = 0x00007FFFFFFFF000ULL + 0x1000;
        uint64_t user_stack_base = user_stack_top - SCHEDULER_STACKSZ;

        map_region((uint64_t *)PHYS_TO_VIRTUAL(parent->vmc->pml4_table),
                   (uint64_t)thread->user_stack, user_stack_base,
                   SCHEDULER_STACK_PAGES, PMLE_USER_READ_WRITE);

        ctx->rip    = (uint64_t)entry;
        ctx->cs     = 0x1B | 3;
        ctx->ss     = 0x23 | 3;
        ctx->ds     = 0x23 | 3;
        ctx->rflags = 0x202;
        ctx->rbp    = 0;
        ctx->rsp    = user_stack_top - 16;

        if (!is_address_canonical(ctx->rsp)) {
            debugf_warn("Cannot create usermode thread TID=%d: stack address "
                        "%p is not canonical\n",
                        thread->tid, (void *)ctx->rsp);
            pmm_free((void *)VIRT_TO_PHYSICAL(thread->kernel_stack),
                     SCHEDULER_STACK_PAGES);
            pmm_free((void *)VIRT_TO_PHYSICAL(thread->user_stack),
                     SCHEDULER_STACK_PAGES);
            kfree(thread->fpu);
            kfree(ctx);
            kfree(thread);
            return -1;
        }

        debugf_debug(
            "Created usermode thread TID=%d entry=%p ustack=%p kstack=%p\n",
            thread->tid, entry, (void *)ctx->rsp, thread->kernel_stack);
    } else {
        thread->kernel_stack =
            (void *)PHYS_TO_VIRTUAL(pmm_alloc_pages(SCHEDULER_STACK_PAGES));
        thread->user_stack = NULL;

        ctx->rip    = (uint64_t)entry;
        ctx->cs     = 0x08;
        ctx->ss     = 0x10;
        ctx->ds     = 0x10;
        ctx->rflags = 0x202;
        ctx->rsp    = (uint64_t)(thread->kernel_stack + SCHEDULER_STACKSZ - 8);

        debugf_debug("Created kernel thread TID=%d entry=%p kstack=%p\n",
                     thread->tid, entry, (void *)ctx->rsp);
    }

    thread->regs = ctx;

    parent->threads =
        krealloc(parent->threads, sizeof(tcb_t *) * parent->thread_count);
    parent->threads[thread->tid] = thread;

    spinlock_acquire(&SCHEDULER_LOCK);

    int cpu                 = get_cpu();
    thread->next            = thread_queues[cpu].head;
    thread_queues[cpu].head = thread;
    thread_queues[cpu].count++;

    if (!current_threads[cpu]) {
        current_threads[cpu] = thread;
    }

    spinlock_release(&SCHEDULER_LOCK);

    return thread->tid;
}

tcb_t *get_current_tcb() {
    int cpu = get_cpu();
    return current_threads[cpu];
}

pcb_t *pcb_lookup(int pid) {
    int cpu  = get_cpu();
    tcb_t *t = thread_queues[cpu].head;
    pcb_t *p = NULL;
    for (; t != NULL; t = t->next) {
        p = t->parent;
        if (!p) { // ...somehow??
            continue;
        }

        if (p->pid == pid) {
            break;
        }
    }

    return p;
}

tcb_t *tcb_lookup(int pid, int tid) {
    int cpu  = get_cpu();
    tcb_t *t = thread_queues[cpu].head;

    for (; t != NULL; t = t->next) {
        if (!t->parent) {
            continue;
        }

        pcb_t *parent = t->parent;
        if (parent->pid != pid) {
            continue;
        }

        if (t->tid != tid) {
            continue;
        }
    }

    return t;
}

// creates the "init process" per-CPU
int init_cpu_scheduler(void (*p)()) {
    proc_create(p, 0, "initproc");
    return 0;
}

int pcb_destroy(int pid) {
    pcb_t *p = pcb_lookup(pid);
    if (!p) {
        return ENULLPTR;
    }

    p->state = PROC_DEAD;
    for (int i = 0; i < p->thread_count; i++) {
        if (!p->threads[i]) {
            continue;
        }

        tcb_t *t = p->threads[i];
        t->state = THREAD_DEAD;
    }

    // also remove it from the queue in the next yield just like the thread

    return EOK;
}

void thread_push_to_queue(tcb_t *to_push) {
    int cpu   = get_cpu();
    tcb_t **p = &thread_queues[cpu].head;

    while (*p && *p != to_push) {
        p = &(*p)->next;
    }
    if (*p == NULL) {
        return;
    }
    *p            = to_push->next;
    to_push->next = NULL;

    tcb_t **q = &thread_queues[cpu].head;
    while (*q) {
        q = &(*q)->next;
    }
    *q = to_push;
}

void thread_remove_from_queue(tcb_t *to_remove) {
    int cpu   = get_cpu();
    tcb_t **p = &thread_queues[cpu].head;

    while (*p && *p != to_remove) {
        p = &(*p)->next;
    }

    if (*p == NULL) {
        return;
    }

    *p              = to_remove->next;
    to_remove->next = NULL;
}

int thread_destroy(int pid, int tid) {
    tcb_t *t = tcb_lookup(pid, tid);
    if (!t) {
        return ENULLPTR;
    }

    t->state = THREAD_DEAD;

    // thread_remove_from_queue(t);
    // actually cleanup in the next yield

    return EOK;
}

pcb_t *get_current_pcb() {
    int cpu        = get_cpu();
    tcb_t *current = current_threads[cpu];
    return current ? current->parent : NULL;
}

// destroys current process
int proc_exit() {
    int cpu        = get_cpu();
    tcb_t *current = current_threads[cpu];

    int ret = pcb_destroy(current->parent->pid);

    debugf("Process %d killed!\n", current->parent->pid);

    return ret;
}

void yield(registers_t *regs) {
    int cpu        = get_cpu();
    tcb_t *current = current_threads[cpu];
    tcb_t *next;

    if (!current) {
        current = pick_next_thread(cpu);
    }

    switch (current->state) {
    case THREAD_READY:
        next = current;
        break;

    case THREAD_RUNNING:
        if (--current->time_slice > 0) {
            return;
        }

        fpu_save(current->fpu);

        if (regs) {
            memcpy(current->regs, regs, sizeof(registers_t));
        }

        current->state      = THREAD_READY;
        current->time_slice = SCHEDULER_THREAD_TS;

        thread_push_to_queue(current);
        next = pick_next_thread(cpu);
        break;

    case THREAD_WAITING:
    case THREAD_DEAD:
        thread_remove_from_queue(current);
        debugf_debug("Cleaned up thread TID=%d, PID=%d\n", current->tid,
                     current->parent->pid);
        if (current->parent->state == PROC_DEAD) {
            pmm_free((void *)VIRT_TO_PHYSICAL(current->kernel_stack),
                     SCHEDULER_STACK_PAGES);
            if (current->user_stack) {
                pmm_free((void *)VIRT_TO_PHYSICAL(current->user_stack),
                         SCHEDULER_STACK_PAGES);
            }
            kfree(current->fpu);
            kfree(current->regs);
            kfree(current->parent->threads);
            kfree(current->parent->name);
            kfree(current->parent->vmc->pml4_table);
            kfree(current->parent);
        }
        next = pick_next_thread(cpu);
        break;
    }

    if (!next) {
        mprintf_warn("No more processes. System idle.\n");
        scheduler_idle();
    }

    current_threads[cpu] = next;
    next->state          = THREAD_RUNNING;

    if (next->parent && next->parent->vmc) {
        uint64_t pml4_phys =
            VIRT_TO_PHYSICAL((uint64_t)next->parent->vmc->pml4_table);
        vmc_switch(next->parent->vmc);
        _load_pml4((uint64_t *)pml4_phys);
    }

    if (next && (next->flags & TF_MODE_USER)) {
        uint64_t kernel_stack_top =
            (uint64_t)next->kernel_stack + SCHEDULER_STACKSZ;
        tss_set_kernel_stack(kernel_stack_top);

        debugf_debug("Switching to usermode thread TID=%d, kernel_stack=%p\n",
                     next->tid, (void *)kernel_stack_top);
    }

    fpu_restore(next->fpu);

    if (!regs) {
        context_load(next->regs);
    } else {
        memcpy(regs, next->regs, sizeof(registers_t));
    }
}
