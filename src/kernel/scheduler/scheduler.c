#include "scheduler.h"

#include <autoconf.h>
// #include <fs/vfs/vfs.h>
#include <gdt/gdt.h>
#include <interrupts/isr.h>
#include <kernel.h>
#include <memory/heap/kheap.h>
#include <memory/vmm/vmm.h>
#include <paging/paging.h>
#include <smp/smp.h>
#include <spinlock.h>
#include <util/assert.h>

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

scheduler_manager_t *scheduler_manager;

void idle(void) {
    for (;;)
        ;
}

proc_t *create_idle_process(uint8_t core) {
    proc_t *idle_proc       = kmalloc(sizeof(proc_t));
    idle_proc->pid          = scheduler_manager->next_pid++;
    idle_proc->whoami.user  = 0;
    idle_proc->whoami.group = 0;
    idle_proc->pml4         = get_kernel_pml4();

    asm volatile("movq %%rsp, %0" : "=r"(idle_proc->regs.rsp));
    idle_proc->regs.rsp -= PROC_STACK_SIZE;

    idle_proc->regs.rbp    = idle_proc->regs.rsp;
    idle_proc->regs.rflags = 0x202;

    idle_proc->regs.rip = (uint64_t)idle;
    idle_proc->regs.cs  = GDT_CODE_SEGMENT;
    idle_proc->regs.ss  = GDT_DATA_SEGMENT;
    idle_proc->regs.ds  = GDT_DATA_SEGMENT;

    idle_proc->time_slice = PROC_TIME_SLICE;
    idle_proc->sched_flags =
        SCHED_PROC_KERNEL_PAGE_MAP | SCHED_PROC_KERNEL_STACK;
    idle_proc->current_fd     = 0;
    idle_proc->state          = PROC_STATE_RUNNING;
    idle_proc->current_core   = core;
    idle_proc->preferred_core = core;

    idle_proc->next  = NULL;
    idle_proc->errno = 0;

    return idle_proc;
}

void scheduler_init() {
    scheduler_manager = kmalloc(sizeof(scheduler_manager_t));

    bootloader_data *bootloader_data = get_bootloader_data();
    scheduler_manager->core_count    = bootloader_data->cpu_count;
    scheduler_manager->core_schedulers =
        kmalloc(sizeof(core_scheduler_t *) * bootloader_data->cpu_count);

    scheduler_manager->process_list_head     = NULL;
    scheduler_manager->process_count         = 0;
    scheduler_manager->next_pid              = 0;
    scheduler_manager->load_balance_interval = 0;
    scheduler_manager->last_load_balance     = 0;

    for (size_t i = 0; i < scheduler_manager->core_count; i++) {
        scheduler_manager->core_schedulers[i] =
            kmalloc(sizeof(core_scheduler_t));
        // lapic_timer_init(); we maybe just init this outside of scheduler
        scheduler_init_cpu(i);
    }

    spinlock_release(&scheduler_manager->glob_lock);

#ifdef CONFIG_SCHED_DEBUG
    debugf_debug("Scheduler initialized with %zu cores\n",
                 scheduler_manager->core_count);
#endif
}

void scheduler_init_cpu(uint8_t core) {
    scheduler_manager->core_schedulers[core]->core_id      = core;
    scheduler_manager->core_schedulers[core]->current_proc = NULL;
    scheduler_manager->core_schedulers[core]->idle_proc =
        create_idle_process(core);
    scheduler_manager->core_schedulers[core]->run_queue_head     = NULL;
    scheduler_manager->core_schedulers[core]->run_queue_tail     = NULL;
    scheduler_manager->core_schedulers[core]->run_queue_size     = 0;
    scheduler_manager->core_schedulers[core]->context_switches   = 0;
    scheduler_manager->core_schedulers[core]->last_schedule_time = 0;
    scheduler_manager->core_schedulers[core]->flags              = 0;
    scheduler_manager->core_schedulers[core]->default_time_slice =
        PROC_TIME_SLICE;

    spinlock_release(&scheduler_manager->core_schedulers[core]->lock);
}

proc_t *scheduler_add(void (*entry_point)(), int flags) {
    asm("cli");

    uint8_t least_loaded_cpu      = 0;
    size_t least_loaded_cpu_count = SIZE_MAX;
    for (size_t i = 0; i < scheduler_manager->core_count; i++) {
        if (scheduler_manager->core_schedulers[i]->run_queue_size <
            least_loaded_cpu_count) {
            least_loaded_cpu_count =
                scheduler_manager->core_schedulers[i]->run_queue_size;
            least_loaded_cpu = i;
        }
    }

    proc_t *proc = kmalloc(sizeof(proc_t));
    proc->pid    = scheduler_manager->next_pid;
    scheduler_manager->next_pid++;
    proc->whoami.user  = 0;
    proc->whoami.group = 0;
    if (flags & SCHED_PROC_KERNEL_PAGE_MAP) {
        proc->pml4 = get_kernel_pml4();
    } else {
        proc->pml4 = (uint64_t *)pmm_alloc_page();
        pagemap_copy_to(proc->pml4);
        copy_range_to_pagemap(proc->pml4, get_kernel_pml4(), 0x1000, 0x10000);
    }

    memset(&proc->regs, 0, sizeof(registers_t));

    proc->regs.ds = GDT_DATA_SEGMENT;
    proc->regs.cs = GDT_CODE_SEGMENT;
    proc->regs.ss = GDT_DATA_SEGMENT;

    if (flags & SCHED_PROC_KERNEL_STACK) {
        asm volatile("movq %%rsp, %0" : "=r"(proc->regs.rsp));
        proc->regs.rsp -= PROC_STACK_SIZE;
    } else {
        proc->regs.rsp =
            ((uint64_t)PHYS_TO_VIRTUAL(pmm_alloc_pages(PROC_STACK_PAGES))) +
            (PROC_STACK_SIZE);
    }

    proc->regs.rbp    = proc->regs.rsp;
    proc->regs.rflags = 0x202;
    proc->regs.rip    = (uint64_t)entry_point;

    proc->time_slice     = PROC_TIME_SLICE;
    proc->sched_flags    = flags;
    proc->current_fd     = 0;
    proc->state          = PROC_STATE_READY;
    proc->current_core   = least_loaded_cpu;
    proc->preferred_core = least_loaded_cpu;
    proc->next           = NULL;
    proc->errno          = 0;

    if (scheduler_manager->process_list_head == NULL) {
        scheduler_manager->process_list_head = proc;
    } else {
        proc_t *last_proc = scheduler_manager->process_list_head;
        while (last_proc->next != NULL) {
            last_proc = last_proc->next;
        }
        last_proc->next = proc;
    }
    scheduler_manager->process_count++;

    core_scheduler_t *sched =
        scheduler_manager->core_schedulers[least_loaded_cpu];
    if (sched->run_queue_head == NULL) {
        sched->run_queue_head = proc;
        sched->run_queue_tail = proc;
    } else {
        sched->run_queue_tail->next = proc;
        sched->run_queue_tail       = proc;
    }
    sched->run_queue_size++;

    proc->next  = NULL;
    proc->state = PROC_STATE_READY;

#ifdef CONFIG_SCHED_DEBUG
    debugf_debug("Added process %d to CPU %d, RIP: 0x%.16llx, RBP 0x%.16llx, "
                 "PML4: 0x%.16llx\n",
                 proc->pid, least_loaded_cpu, proc->regs.rip, proc->regs.rbp,
                 proc->pml4);
#endif
    asm("sti");
    return proc;
}

void scheduler_remove(proc_t *proc) {
    asm("cli");
    if (scheduler_manager->process_list_head == proc) {
        scheduler_manager->process_list_head = proc->next;
    } else {
        proc_t *prev_proc = scheduler_manager->process_list_head;
        while (prev_proc->next != proc) {
            prev_proc = prev_proc->next;
        }
        prev_proc->next = proc->next;
    }
    scheduler_manager->process_count--;

    core_scheduler_t *sched =
        scheduler_manager->core_schedulers[proc->current_core];
    if (sched->run_queue_head == proc) {
        sched->run_queue_head = proc->next;
    } else {
        proc_t *prev_proc = sched->run_queue_head;
        while (prev_proc->next != proc) {
            prev_proc = prev_proc->next;
        }
        prev_proc->next = proc->next;
    }
    sched->run_queue_size--;
    asm("sti");
}

proc_t *get_current_process() {
    asm("cli");
    core_scheduler_t *sched = scheduler_manager->core_schedulers[get_cpu()];
    if (sched->current_proc == NULL) {
        return sched->idle_proc;
    }
    asm("sti");
    return sched->current_proc;
}

void scheduler_switch_context(proc_t *proc, registers_t *current_regs) {
    memcpy(&proc->regs, current_regs, sizeof(registers_t));
    _load_pml4(proc->pml4);
}

void scheduler_schedule(void *ctx) {
    asm("cli");
    _load_pml4(get_kernel_pml4());

    core_scheduler_t *sched = scheduler_manager->core_schedulers[get_cpu()];

    registers_t *regs = ctx;

    if (sched->current_proc) {
        memcpy(&sched->current_proc->regs, regs, sizeof(registers_t));
    }

    if (sched->run_queue_head) {
        proc_t *next_proc     = sched->run_queue_head;
        sched->run_queue_head = next_proc->next;
        if (!sched->run_queue_head) {
            sched->run_queue_tail = NULL;
        }
        sched->run_queue_size--;

        if (sched->current_proc &&
            sched->current_proc->state == PROC_STATE_READY) {
            if (sched->run_queue_tail) {
                sched->run_queue_tail->next = sched->current_proc;
            } else {
                sched->run_queue_head = sched->current_proc;
            }
            sched->run_queue_tail = sched->current_proc;
            sched->run_queue_size++;
        }

        sched->current_proc = next_proc;
        memcpy(regs, &next_proc->regs, sizeof(registers_t));
        _load_pml4(next_proc->pml4);
    } else {
        if (sched->current_proc != sched->idle_proc) {
            sched->current_proc    = sched->idle_proc;
            sched->idle_proc->next = NULL; // Ensure idle proc's next is NULL
            memcpy(regs, &sched->idle_proc->regs, sizeof(registers_t));
            _load_pml4(sched->idle_proc->pml4);
        }
    }

    sched->context_switches++;
    asm("sti");
}