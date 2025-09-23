#include "memory/heap/kheap.h"
#include "pci/pci.h"
#include <io.h>
#include <module/modinfo.h>
#include <stdio.h>

const modinfo_t modinfo = {
    .name        = "rtl8139_driver",
    .version     = "0.0.1",
    .author      = "NotNekodev",
    .description = "Realtek RTL-8139 PCI Fast Ethernet Adapter Network Driver",
    .license     = "MIT",
    .url         = "https://github.com/purplek2/PurpleK2",
    .priority    = MOD_PRIO_LOW,
    .deps        = {"kernel", NULL}};

#define RTL8139_VENDOR_ID 0x10EC
#define RTL8139_DEVICE_ID 0x8139
#define RTL8139_MAC0      0x00

static pci_device_t *rtl8139_dev = NULL;

void module_exit() {
    rtl8139_dev = NULL;
}

void module_entry() {
    pci_device_t *dev = get_pcihead();
    while (dev) {
        if (dev->vendor_id == RTL8139_VENDOR_ID &&
            dev->device_id == RTL8139_DEVICE_ID) {
            rtl8139_dev = dev;
            break;
        }
        dev = dev->next;
    }

    if (!rtl8139_dev) {
        kprintf_warn("RTL8139 NIC not found!\n");
        return;
    }

    uint16_t cmd = pci_config_read(rtl8139_dev->bus, rtl8139_dev->device,
                                   rtl8139_dev->function, 0x04) &
                   0xFFFF;
    cmd |= (1 << 2);
    pci_config_write(rtl8139_dev->bus, rtl8139_dev->device,
                     rtl8139_dev->function, 0x04, cmd);

    uint32_t io_base = rtl8139_dev->bar[0];
    if (!io_base) {
        kprintf_warn("RTL8139 I/O BAR not set!\n");
        return;
    }

    kprintf(
        "RTL8139 NIC found at bus %u, device %u, function %u, I/O base 0x%x\n",
        rtl8139_dev->bus, rtl8139_dev->device, rtl8139_dev->function, io_base);

    uint8_t mac[6];
    for (int i = 0; i < 6; i++) {
        mac[i] = _inb(io_base + RTL8139_MAC0 + i);
    }

    kprintf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}
