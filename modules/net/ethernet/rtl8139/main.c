#include "memory/heap/kheap.h"
#include "pci/pci.h"
#include "rtl8139.h"
#include <io.h>
#include <module/modinfo.h>
#include <stdio.h>

const modinfo_t modinfo = {
    .name        = "rtl8139_driver",
    .version     = "0.0.2",
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
    if (rtl8139_dev) {
        kprintf("RTL8139: Module exiting, cleaning up...\n");
        rtl8139_cleanup();
        rtl8139_dev = NULL;
    }
}

void module_entry() {
    kprintf("RTL8139: Module loading...\n");

    // Search for RTL8139 device in PCI bus
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

    kprintf("RTL8139 NIC found at bus %u, device %u, function %u\n",
            rtl8139_dev->bus, rtl8139_dev->device, rtl8139_dev->function);

    // Enable PCI device - set bus mastering and I/O space access
    uint16_t cmd = pci_config_read(rtl8139_dev->bus, rtl8139_dev->device,
                                   rtl8139_dev->function, 0x04) &
                   0xFFFF;

    // Enable I/O Space (bit 0) and Bus Mastering (bit 2)
    cmd |= (1 << 0) | (1 << 2);
    pci_config_write(rtl8139_dev->bus, rtl8139_dev->device,
                     rtl8139_dev->function, 0x04, cmd);

    kprintf("RTL8139: PCI command register set to 0x%x\n", cmd);

    // Get I/O base address from BAR0
    uint32_t io_base = rtl8139_dev->bar[0] & 0xFFFFFFFC; // Mask out lower bits
    if (!io_base) {
        kprintf_warn("RTL8139 I/O BAR not set!\n");
        return;
    }

    kprintf("RTL8139: I/O base address: 0x%x\n", io_base);

    // Read MAC address from device registers
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) {
        mac[i] = _inb(io_base + RTL8139_MAC0 + i);
    }

    kprintf("RTL8139 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1],
            mac[2], mac[3], mac[4], mac[5]);

    // Initialize the RTL8139 driver
    rtl8139_init(io_base, mac);

    // Add a delay to ensure initialization is complete
    for (volatile int i = 0; i < 100000; i++)
        ;

    // Test: Send ARP request
    uint32_t my_ip = 0xC0A801FE; // 192.168.1.254 (changed to avoid conflicts)
    uint32_t target_ip = 0xC0A80101; // 192.168.1.1 (gateway)

    kprintf("RTL8139: Sending test ARP request...\n");
    rtl8139_send_arp_request(my_ip, target_ip);

    kprintf("ARP request sent from %d.%d.%d.%d to %d.%d.%d.%d\n",
            (my_ip >> 24) & 0xFF, (my_ip >> 16) & 0xFF, (my_ip >> 8) & 0xFF,
            my_ip & 0xFF, (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
            (target_ip >> 8) & 0xFF, target_ip & 0xFF);

    // Add another delay to ensure transmission completes before module might
    // exit
    for (volatile int i = 0; i < 100000; i++)
        ;

    kprintf("RTL8139: Module initialization completed\n");
}