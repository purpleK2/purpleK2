#include "isr.h"
#include "elf/sym.h"

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

extern struct limine_hhdm_request *hhdm_request;

isrHandler isr_handlers[IDT_MAX_DESCRIPTORS];

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

void isr_init() {
    for (int i = 0; i < 256; i++) {
        idt_gate_enable(i);
    }

    idt_gate_disable(0x80);
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

void panic_common(void *ctx) {
    registers_t *regs = ctx;

    print_reg_dump(regs);

    // stacktrace
    mprintf("\n\n --- STACK TRACE ---\n");
    uint64_t *rbp = (uint64_t *)regs->rbp;
    int frame     = 0;

    const char *rip_name =
        resolve_symbol_name(get_bootloader_data()->kernel_file_data,
                            get_bootloader_data()->kernel_file_size, regs->rip);
    mprintf("[RIP][%p] %s\n", regs->rip, rip_name ? rip_name : "unknown");

    while (rbp) {
        uint64_t return_addr =
            rbp[1]; // Return address (points after call instruction)
        uint64_t *prev_rbp = (uint64_t *)rbp[0];

        uint64_t approx_func_addr = return_addr;

        const char *func_name = resolve_symbol_name(
            get_bootloader_data()->kernel_file_data,
            get_bootloader_data()->kernel_file_size, approx_func_addr);
        if (func_name) {
            mprintf("[%d][%p] %s\n", frame, rbp, func_name);
        } else {
            mprintf("[%d][%p] func addr: %llx\n", frame, rbp, approx_func_addr);
        }

        rbp = prev_rbp;
        frame++;

        if (frame > 20 || !rbp || (uint64_t)rbp < 0x1000)
            break;
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
