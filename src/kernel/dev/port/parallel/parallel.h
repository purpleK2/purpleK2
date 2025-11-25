#ifndef DEV_PARALLEL_H
#define DEV_PARALLEL_H

#include <../arch/x86_64/io.h>
#include <dev/device.h>
#include <memory/heap/kheap.h>
#include <stddef.h>
#include <stdint.h>
#include <util/string.h>

#define LPT1_BASE    0x378
#define DATA_PORT    (LPT1_BASE + 0)
#define STATUS_PORT  (LPT1_BASE + 1)
#define CONTROL_PORT (LPT1_BASE + 2)
#define ECP_ECR      (LPT1_BASE + 0x402)

#define STATUS_BUSY      (1 << 7)
#define STATUS_ACK       (1 << 6)
#define STATUS_PAPER_OUT (1 << 5)
#define STATUS_SELECT    (1 << 4)
#define STATUS_ERROR     (1 << 3)

#define CONTROL_STROBE    (1 << 0)
#define CONTROL_AUTO_FEED (1 << 1)
#define CONTROL_INIT      (1 << 2)
#define CONTROL_SELECT_IN (1 << 3)
#define CONTROL_IRQ       (1 << 4)
#define CONTROL_BIDIR     (1 << 5)

#define ECR_MODE_STANDARD 0x00
#define ECR_MODE_EPP      0x80
#define ECR_MODE_ECP      0x20

int lpt1_status();
void lpt1_write(uint8_t data);
uint8_t lpt1_read();

int dev_lpt1_read(struct device *dev, void *buffer, size_t size, size_t offset);
int dev_lpt1_write(struct device *dev, const void *buffer, size_t size,
                   size_t offset);
int dev_lpt1_ioctl(struct device *dev, int request, void *arg);

void dev_parallel_init();

#endif // DEV_PARALLEL_H