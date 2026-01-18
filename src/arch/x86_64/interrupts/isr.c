#include "isr.h"
#include "elf/sym.h"
#include "loader/module/module_loader.h"
#include "scheduler/scheduler.h"
#include "syscalls/syscall.h"

#include <apic/lapic/lapic.h>
#include <gdt/gdt.h>
#include <idt/idt.h>
#include <kernel.h>
#include <limine.h>
#include <smp/ipi.h>
#include <smp/smp.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern struct limine_hhdm_request *hhdm_request;

isrHandler isr_handlers[IDT_MAX_DESCRIPTORS];

struct stackFrame {
    struct stackFrame *rbp;
    uint64_t rip;
};

static const char *const exceptions[] = {"Divide by zero error",
                                         "Debug",
                                         "Non-maskable Interrupt",
                                         "Breakpoint",
                                         "Overflow",
                                         "Bound Range Exceeded",
                                         "Invalid Opcode",
                                         "Device Not Available",
                                         "Double Fault",
                                         "Coprocessor Segment Overrun",
                                         "Invalid TSS",
                                         "Segment Not Present",
                                         "Stack-Segment Fault",
                                         "General Protection Fault",
                                         "Page Fault",
                                         "",
                                         "x87 Floating-Point Exception",
                                         "Alignment Check",
                                         "Machine Check",
                                         "SIMD Floating-Point Exception",
                                         "Virtualization Exception",
                                         "Control Protection Exception ",
                                         "",
                                         "",
                                         "",
                                         "",
                                         "",
                                         "",
                                         "Hypervisor Injection Exception",
                                         "VMM Communication Exception",
                                         "Security Exception",
                                         ""};

void isr_syscall(registers_t *ctx) {
    long ret = handle_syscall(ctx);

    ctx->rax = ret;

    tcb_t *current = get_current_tcb();
    if (current && (current->flags & TF_MODE_USER) && current->tls.base_virt) {
        _cpu_set_msr(0xC0000100, (uint64_t)current->tls.base_virt);
    }
}

static void isr_debug(registers_t *ctx) {
    debugf_warn("Debug exception at RIP=0x%llx\n", ctx->rip);

    ctx->rflags &= ~(1ULL << 8);

    ctx->rip += 1;
}

void isr_init() {
    for (int i = 0; i < 256; i++) {
        idt_gate_enable(i);
    }

    isr_registerHandler(0x80, isr_syscall);
    isr_registerHandler(0x1, isr_debug);
}

void print_reg_dump(registers_t *ctx) {
    debugf(ANSI_COLOR_BLUE);
    mprintf("\nRegister dump:\n\n");

    mprintf("--- GENERAL PURPOSE REGISTERS ---\n");
    mprintf("rax: 0x%.016llx r8: 0x%.16llx\n"
            "rbx: 0x%.016llx r9: 0x%.16llx\n"
            "rcx: 0x%.016llx r10: 0x%.16llx\n"
            "rdx: 0x%.016llx r11: 0x%.16llx\n"
            "\t\t\tr12: 0x%.016llx\n"
            "\t\t\tr13: 0x%.016llx\n"
            "\t\t\tr14: 0x%.016llx\n"
            "\t\t\tr15: 0x%.016llx\n",
            ctx->rax, ctx->r8, ctx->rbx, ctx->r9, ctx->rcx, ctx->r10, ctx->rdx,
            ctx->r11, ctx->r12, ctx->r13, ctx->r14, ctx->r15);

    mprintf("\n--- SEGMENT REGS ---\n");
    mprintf("\tcs (Code segment):   %llx\n"
            "\tds (Data segment):   %llx\n"
            "\tss (Stack segment):  %llx\n",
            ctx->cs, ctx->ds, ctx->ss);

    mprintf("\n--- FLAGS, POINTER AND INDEX REGISTERS ---\n");
    mprintf("\teflags:%llx\n"
            "\trip (Instruction address):  %llx\n"
            "\trbp (Base pointer):         %llx\n"
            "\trsp (Stack pointer):        %llx\n"
            "\trdi:                        %llx\n"
            "\trsi:                        %llx\n",
            ctx->rflags, ctx->rip, ctx->rbp, ctx->rsp, ctx->rdi, ctx->rsi);
}

static void print_symbol(int frame, uintptr_t addr) {
    static struct SymbolInfo info = {0};
    memset(&info, 0, sizeof(info)); // because its static
    const char *mod_name = NULL;

    // Check kernel
    if (currently_running_mod &&
        addr >= (uintptr_t)currently_running_mod->base_address &&
        addr < (uintptr_t)currently_running_mod->end_address &&
        resolve_symbol(currently_running_mod->ehdr,
                       (uintptr_t)currently_running_mod->end_address -
                           (uintptr_t)currently_running_mod->base_address,
                       addr - (uintptr_t)currently_running_mod->base_address,
                       &info)) {
        mod_name = currently_running_mod->modinfo->name;
    } else {
        mod_name = "kernel";
        resolve_symbol(get_bootloader_data()->kernel_file_data,
                       get_bootloader_data()->kernel_file_size, addr, &info);
    }

    if (info.name) {
        if (strcmp(mod_name, "kernel") == 0) {
            size_t offset = addr - info.start;
            if (info.size > 0)
                mprintf("[%d][%p] %s:%s+0x%zx/0x%zx\n", frame, (void *)addr,
                        mod_name, info.name, offset, info.size);
            else
                mprintf("[%d][%p] %s:%s+0x%zx\n", frame, (void *)addr, mod_name,
                        info.name, offset);
        } else {
            size_t offset =
                addr -
                ((uintptr_t)currently_running_mod->base_address + info.start);
            if (info.size > 0)
                mprintf(
                    "[%d][%p] %s:%s+0x%zx/0x%zx -- (0x%zx)\n", frame,
                    (void *)addr, mod_name, info.name, offset, info.size,
                    (addr - (uintptr_t)currently_running_mod->base_address));
            else
                mprintf(
                    "[%d][%p] %s:%s+0x%zx  -- (0x%zx)\n", frame, (void *)addr,
                    mod_name, info.name, offset,
                    (addr - (uintptr_t)currently_running_mod->base_address));
        }
    } else {
        mprintf("[%d][%p] <unknown>\n", frame, (void *)addr);
    }
}

static uint8_t stack_failed_count = -1;

void panic_common(registers_t *ctx) {

    print_reg_dump(ctx);

    stack_failed_count++;
    if (stack_failed_count > 0) {
        mprintf(
            "\nStack trace failed before. Not attempting to print it again.\n");
        mprintf("\nPANIC LOG END --- HALTING ---\n");
        debugf(ANSI_COLOR_RESET);
        asm("cli");
        _hcf();
    }

    // stacktrace
    mprintf("\n\n --- STACK TRACE ---\n");
    struct stackFrame *stack = (struct stackFrame *)ctx->rbp;
    int frame                = 0;

    print_symbol(frame++, ctx->rip);

    while (stack) {
        print_symbol(frame++, stack->rip);
        stack = (struct stackFrame *)stack->rbp;
    }

    mprintf("\nPANIC LOG END --- HALTING ---\n");
    debugf(ANSI_COLOR_RESET);
    asm("cli");
    _hcf();
}

void isr_handler(registers_t *ctx) {
    uint64_t cpu = 0;
    if (is_lapic_enabled())
        cpu = lapic_get_id();

    UNUSED(cpu);

    if (isr_handlers[ctx->interrupt] != NULL) {
        isr_handlers[ctx->interrupt](ctx);
    } else if (ctx->interrupt >= 32) {
        debugf_warn("Unhandled interrupt %d on CPU %hhu\n", ctx->interrupt,
                    lapic_get_id());
    } else {
        stdio_panic_init();

        debugf(ANSI_COLOR_BLUE);

        bsod_init();

        uint64_t cpu = 0;
        if (is_lapic_enabled())
            cpu = lapic_get_id();

        mprintf("KERNEL PANIC! \"%s\" (Exception n. %d) on CPU %hhu\n",
                exceptions[ctx->interrupt], ctx->interrupt, cpu);
        mprintf("\terrcode: %llx\n", ctx->error);

        panic_common(ctx);

        _hcf();
    }
}

void isr_registerHandler(int interrupt, isrHandler handler) {
    isr_handlers[interrupt] = handler;
    idt_gate_enable(interrupt);
}
