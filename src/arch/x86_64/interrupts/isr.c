#include "isr.h"
#include "elf/sym.h"
#include "loader/module/module_loader.h"
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

void isr_syscall(void *ctx) {
    registers_t *regs = ctx;

    long syscall_num = regs->rax;
    long arg1        = regs->rdi;
    long arg2        = regs->rsi;
    long arg3        = regs->rdx;
    long arg4        = regs->r8;
    long arg5        = regs->r9;
    long arg6        = regs->r10;

    long ret = handle_syscall(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);

    regs->rax = ret;
}

void isr_init() {
    for (int i = 0; i < 256; i++) {
        idt_gate_enable(i);
    }

    isr_registerHandler(0x80, isr_syscall);
}

void print_reg_dump(void *ctx) {
    debugf(ANSI_COLOR_BLUE);

    registers_t *regs = ctx;

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
            regs->rax, regs->r8, regs->rbx, regs->r9, regs->rcx, regs->r10,
            regs->rdx, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);

    mprintf("\n--- SEGMENT REGS ---\n");
    mprintf("\tcs (Code segment):   %llx\n"
            "\tds (Data segment):   %llx\n"
            "\tss (Stack segment):  %llx\n",
            regs->cs, regs->ds, regs->ss);

    mprintf("\n--- FLAGS, POINTER AND INDEX REGISTERS ---\n");
    mprintf("\teflags:%llx\n"
            "\trip (Instruction address):  %llx\n"
            "\trbp (Base pointer):         %llx\n"
            "\trsp (Stack pointer):        %llx\n"
            "\trdi:                        %llx\n"
            "\trsi:                        %llx\n",
            regs->rflags, regs->rip, regs->rbp, regs->rsp, regs->rdi,
            regs->rsi);
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

void panic_common(void *ctx) {
    registers_t *regs = ctx;

    print_reg_dump(regs);

    // stacktrace
    mprintf("\n\n --- STACK TRACE ---\n");
    struct stackFrame *stack = (struct stackFrame *)regs->rbp;
    int frame                = 0;

    print_symbol(frame++, regs->rip);

    while (stack) {
        print_symbol(frame++, stack->rip);
        stack = (struct stackFrame *)stack->rbp;
    }

    mprintf("\nPANIC LOG END --- HALTING ---\n");
    debugf(ANSI_COLOR_RESET);
    asm("cli");
    _hcf();
}

void isr_handler(void *ctx) {
    registers_t *regs = ctx;

    uint64_t cpu = 0;
    if (is_lapic_enabled())
        cpu = lapic_get_id();

    UNUSED(cpu);

    if (isr_handlers[regs->interrupt] != NULL) {
        isr_handlers[regs->interrupt](regs);
    } else if (regs->interrupt >= 32) {
        debugf_warn("Unhandled interrupt %d on CPU %hhu\n", regs->interrupt,
                    lapic_get_id());
    } else {
        stdio_panic_init();

        debugf(ANSI_COLOR_BLUE);

        bsod_init();

        uint64_t cpu = 0;
        if (is_lapic_enabled())
            cpu = lapic_get_id();

        mprintf("KERNEL PANIC! \"%s\" (Exception n. %d) on CPU %hhu\n",
                exceptions[regs->interrupt], regs->interrupt, cpu);
        mprintf("\terrcode: %llx\n", regs->error);

        panic_common(regs);

        _hcf();
    }
}

void isr_registerHandler(int interrupt, isrHandler handler) {
    isr_handlers[interrupt] = handler;
    idt_gate_enable(interrupt);
}
