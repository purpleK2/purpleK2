#include "serial.h"

#include <dev/device.h>
#include <io.h>

#include <stdio.h>

int serial_received(int port) {
    return _inb(port + 5) & 1;
}

int is_transmit_empty(int port) {
    return _inb(port + 5) & 0x20;
}

int com1_write(struct device *dev, const void *buffer, size_t size,
               size_t offset) {
    (void)offset;
    (void)dev;

    for (size_t i = 0; i < size; i++) {
        serial_write(COM1, ((char *)buffer)[i]);
    }

    return 0;
}

int com1_read(struct device *dev, void *buffer, size_t size, size_t offset) {
    (void)offset;
    (void)dev;

    for (size_t i = 0; i < size; i++) {
        ((char *)buffer)[i] = serial_read(COM1);
    }

    return 0;
}

void serial_init(int port) {
    _outb(port + 1, 0x00); // disable interrupts
    _outb(port + 3, 0x80); // enable DLAB
    _outb(port + 0, 0x03); // set divisor to 3 (lo byte) 38400 baud
    _outb(port + 1, 0x00); //                  (hi byte)
    _outb(port + 3, 0x03); // 8 bits, no parity, one stop bit
    _outb(port + 2,
          0xC7);           // enable FIFO, clear them, with 14-byte threshold
    _outb(port + 4, 0x0B); // IRQs enabled, RTS/DSR set
    _outb(port + 4, 0x1E); // set in loopback mode, test the serial chip
    _outb(port + 0, 'S');  // test serial chip (send byte 0xAE and check if
                           // serial returns same byte)
    if (_inb(port + 0) != 'S') {
        kprintf_warn("Couldn't initialize serial port 0x%llX\n", port);
        return;
    }

    // If serial is not looped back, set it in normal operation mode
    _outb(port + 4, 0x0F);
}

void serial_write(int port, char c) {
    while (is_transmit_empty(port) == 0)
        ;
    _outb(port, c);
}

char serial_read(int port) {
    while (serial_received(port) == 0)
        ;
    return _inb(port);
}

int com1_ioctl(struct device *dev, int request, void *arg) {
    (void)dev;
    (void)request;
    (void)arg;

    // Implement IOCTL commands here if needed
    return 0;
}

void dev_serial_init() {
    serial_init(COM1);

    device_t *dev = kmalloc(sizeof(device_t));
    memcpy(dev->name, "com1", DEVICE_NAME_MAX);
    dev->write         = com1_write;
    dev->read          = com1_read;
    dev->ioctl         = com1_ioctl;
    dev->dev_node_path = "com1";
    dev->type          = DEVICE_TYPE_CHAR;
    dev->data          = "com1;38400baud;8n1;irq;fifo;works";

    register_device(dev);
}
