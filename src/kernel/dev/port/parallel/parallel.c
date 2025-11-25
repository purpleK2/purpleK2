#include "parallel.h"

#include <dev/device.h>

int lpt1_status() {
    uint8_t status = _inb(STATUS_PORT);

    if (status & STATUS_ERROR)
        return -1;
    if (!(status & STATUS_SELECT))
        return -2;
    if (status & STATUS_PAPER_OUT)
        return -3;
    return 0;
}

void lpt1_write(uint8_t data) {
    while (!(_inb(STATUS_PORT) & STATUS_BUSY))
        ;
    _outb(DATA_PORT, data);
    _outb(CONTROL_PORT, CONTROL_STROBE);
    _outb(CONTROL_PORT, 0);
}

uint8_t lpt1_read() {
    _outb(CONTROL_PORT, CONTROL_BIDIR);
    return _inb(DATA_PORT);
}

int dev_lpt1_read(struct device *dev, void *buffer, size_t size,
                  size_t offset) {
    (void)dev;
    (void)offset;

    if (ECP_ECR) {
        for (size_t i = 0; i < size; i++)
            ((uint8_t *)buffer)[i] = lpt1_read();
    } else {
        return -1;
    }

    return 0;
}

int dev_lpt1_write(struct device *dev, const void *buffer, size_t size,
                   size_t offset) {
    (void)dev;
    (void)offset;

    for (size_t i = 0; i < size; i++)
        lpt1_write(((uint8_t *)buffer)[i]);

    return 0;
}

int dev_lpt1_ioctl(struct device *dev, int request, void *arg) {
    // used for "configuring" the device
    (void)dev;
    (void)request;
    (void)arg;
    return 0;
}

void dev_parallel_init() {
    _outb(CONTROL_PORT, CONTROL_INIT);

    if (ECP_ECR)
        _outb(ECP_ECR, ECR_MODE_ECP);
    if (_inb(ECP_ECR) & ECR_MODE_EPP)
        _outb(ECP_ECR, ECR_MODE_EPP);

    _outb(CONTROL_PORT, CONTROL_SELECT_IN | CONTROL_IRQ | CONTROL_BIDIR);

    char lpt1_info[64];

    if (ECP_ECR) {
        memcpy(lpt1_info, "lpt1;ecp-ecr", sizeof(lpt1_info));
    } else {
        memcpy(lpt1_info, "lpt1;spp", sizeof(lpt1_info));
    }

    device_t *lpt1 = kmalloc(sizeof(device_t));
    memcpy(lpt1->name, "lpt1", DEVICE_NAME_MAX);
    lpt1->type          = DEVICE_TYPE_CHAR;
    lpt1->read          = dev_lpt1_read;
    lpt1->write         = dev_lpt1_write;
    lpt1->ioctl         = dev_lpt1_ioctl;
    lpt1->dev_node_path = "lpt1";
    lpt1->data          = lpt1_info;

    register_device(lpt1);
}
