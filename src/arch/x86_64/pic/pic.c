#include "pic.h"

#include <interrupts/irq.h>

#include "stddef.h"

#include <io.h>

#include <stdio.h>

irq_handler pic_irq_handlers[16];

void pic_sendEOI(uint8_t irq) {
    if (irq >= 8)
        _outb(PIC2_COMMAND, PIC_EOI);
    _outb(PIC1_COMMAND, PIC_EOI);
}

/*
arguments:
        offset1 - vector offset for master PIC
                vectors on the master become offset1..offset1+7
        offset2 - same for slave PIC: offset2..offset2+7
*/
void pic_config(int offset1, int offset2) {
    // uint8_t a1, a2;

    // a1 = inb(PIC1_DATA);                                        // save masks
    // a2 = inb(PIC2_DATA);

    _outb(PIC1_COMMAND,
          PIC_ICW1_INITIALIZE | PIC_ICW1_ICW4); // starts the initialization
                                                // sequence (in cascade mode)
    _io_wait();
    _outb(PIC2_COMMAND, PIC_ICW1_INITIALIZE | PIC_ICW1_ICW4);
    _io_wait();

    _outb(PIC1_DATA, offset1); // ICW2: Master PIC vector offset
    _io_wait();
    _outb(PIC2_DATA, offset2); // ICW2: Slave PIC vector offset
    _io_wait();

    _outb(PIC1_DATA, 0x04); // ICW3: tell Master PIC that there is a slave PIC
                            // at IRQ2 (0000 0100)
    _io_wait();
    _outb(PIC2_DATA,
          0x02); // ICW3: tell Slave PIC its cascade identity (0000 0010)
    _io_wait();

    _outb(
        PIC1_DATA,
        PIC_ICW4_8086); // ICW4: have the PICs use 8086 mode (and not 8080 mode)
    _io_wait();
    _outb(PIC2_DATA, PIC_ICW4_8086);
    _io_wait();

    _outb(PIC1_DATA, 0);
    _io_wait();
    _outb(PIC2_DATA, 0);
    _io_wait();
}

void irq_mask(uint8_t irq_line) {
    uint16_t port;
    uint8_t value;

    if (irq_line < 8) {
        port = PIC1_DATA;
    } else {
        port      = PIC2_DATA;
        irq_line -= 8;
    }
    value = _inb(port) | (1 << irq_line);
    _outb(port, value);
}

void irq_unmask(uint8_t irq_line) {
    uint16_t port;
    uint8_t value;

    if (irq_line < 8) {
        port = PIC1_DATA;
    } else {
        port      = PIC2_DATA;
        irq_line -= 8;
    }
    value = _inb(port) & ~(1 << irq_line);
    _outb(port, value);
}

// Disable the PIC
void pic_disable() {
    _outb(PIC1_COMMAND, PIC_ICW1_INITIALIZE | PIC_ICW1_ICW4);
    _io_wait();
    _outb(PIC2_COMMAND, PIC_ICW1_INITIALIZE | PIC_ICW1_ICW4);
    _io_wait();

    _outb(PIC1_DATA, 0x20);
    _io_wait();
    _outb(PIC1_DATA, 0x28);
    _io_wait();

    _outb(PIC1_DATA, 0x2);
    _io_wait();
    _outb(PIC1_DATA, 0x4);
    _io_wait();

    _outb(PIC1_DATA, PIC_ICW4_8086);
    _io_wait();
    _outb(PIC1_DATA, PIC_ICW4_8086);
    _io_wait();

    // Masks all interrupts
    _outb(PIC1_DATA, 0xff);
    _io_wait();
    _outb(PIC2_DATA, 0xff);
}

/* Helper func */
static uint16_t __pic_get_irq_reg(int ocw3) {
    /* OCW3 to PIC CMD to get the register values.  PIC2 is chained, and
     * represents IRQs 8-15.  PIC1 is IRQs 0-7, with 2 being the chain */
    _outb(PIC1_COMMAND, ocw3);
    _outb(PIC2_COMMAND, ocw3);
    return (_inb(PIC2_COMMAND) << 8) | _inb(PIC1_COMMAND);
}

/* Returns the combined value of the cascaded PICs irq request register */
uint16_t pic_get_irr(void) {
    return __pic_get_irq_reg(PIC_READ_IRR);
}

/* Returns the combined value of the cascaded PICs in-service register
   NOT TO BE CONFUSED WITH INTERRUPT SERVICE ROUTINE!!!*/
uint16_t pic_get_isr(void) {
    return __pic_get_irq_reg(PIC_READ_ISR);
}

void pic_irq_handler(void *ctx) {
    registers_t *regs = ctx;

    int irq = regs->interrupt - PIC_REMAP_OFFSET;

    uint8_t pic_isr = pic_get_isr();
    uint8_t pic_irr = pic_get_irr();

    if (pic_irq_handlers[irq] != NULL) {
        pic_irq_handlers[irq](regs); // tries to handle the interrupt
    } else {
        debugf_warn("Unhandled IRQ %d  ISR=%x  IRR=%x\n", irq, pic_isr,
                    pic_irr);
    }

    pic_sendEOI(irq);
}

void pic_registerHandler(int irq, irq_handler handler) {
    pic_irq_handlers[irq] = handler;
}
