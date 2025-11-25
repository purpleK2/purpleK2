#ifndef PIC_H
#define PIC_H 1

#include <stdint.h>

#include <interrupts/irq.h>
#include <interrupts/isr.h>

#define PIC_REMAP_OFFSET 0x20

#define PIC1_COMMAND 0x20
#define PIC1_DATA    0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA    0xA1

#define PIC_EOI 0x20 // End-of-interrupt command code

#define PIC_READ_IRR 0x0a // OCW3 irq ready next CMD read
#define PIC_READ_ISR 0x0b // OCW3 irq service next CMD read

// Initialization Control Word 1
// -----------------------------
//  0   IC4     if set, the PIC expects to receive ICW4 during initialization
//  1   SGNL    if set, only 1 PIC in the system; if unset, the PIC is cascaded
//  with slave PICs
//              and ICW3 must be sent to controller
//  2   ADI     call address interval, set: 4, not set: 8; ignored on x86, set
//  to 0 3   LTIM    if set, operate in level triggered mode; if unset, operate
//  in edge triggered mode 4   INIT    set to 1 to initialize PIC 5-7 ignored on
//  x86, set to 0
typedef enum {
    PIC_ICW1_ICW4       = 0x01,
    PIC_ICW1_SINGLE     = 0x02,
    PIC_ICW1_INTERVAL4  = 0x04,
    PIC_ICW1_LEVEL      = 0x08,
    PIC_ICW1_INITIALIZE = 0x10
} pic_icw1;

// Initialization Control Word 4
// -----------------------------
//  0   uPM     if set, PIC is in 80x86 mode; if cleared, in MCS-80/85 mode
//  1   AEOI    if set, on last interrupt acknowledge pulse, controller
//  automatically performs
//              end of interrupt operation
//  2   M/S     only use if BUF is set; if set, selects buffer master;
//  otherwise, selects buffer slave 3   BUF     if set, controller operates in
//  buffered mode 4   SFNM    specially fully nested mode; used in systems with
//  large number of cascaded controllers 5-7         reserved, set to 0
typedef enum {
    PIC_ICW4_BUFFER_SLAVE  = 0x00,
    PIC_ICW4_8086          = 0x01,
    PIC_ICW4_AUTO_EOI      = 0x02,
    PIC_ICW4_BUFFER_MASTER = 0x04,
    PIC_ICW4_BUFFERRED     = 0x08,
    PIC_ICW4_SFNM          = 0x10
} pic_icw4;

void pic_irq_handler(void *ctx);

void pic_sendEOI(uint8_t irq);
void pic_config(int offset1, int offset2);

void irq_mask(uint8_t irq_line);
void irq_unmask(uint8_t irq_line);

void pic_disable(void);

uint16_t pic_get_irr(void);
uint16_t pic_get_isr(void);

void pic_registerHandler(int irq, irq_handler handler);

#endif