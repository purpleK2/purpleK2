/**
 * @file drivers/net/rtl8139/rtl8139.c
 * @brief Complete Realtek RTL8139 driver implementation
 */

#include "memory/heap/kheap.h"
#include "memory/pmm/pmm.h"
#include "net/util.h"
#include "paging/paging.h"
#include "pci/pci.h"
#include "rtl8139.h"
#include "util/dump.h"
#include "util/macro.h"
#include <interrupts/irq.h>
#include <io.h>
#include <module/modinfo.h>
#include <net/arp/arp.h>
#include <net/eth/ethernet.h>
#include <net/eth/mac.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const modinfo_t modinfo = {
    .name        = "rtl8139_driver",
    .version     = "0.0.3",
    .author      = "NotNekodev",
    .description = "Realtek RTL-8139 PCI Fast Ethernet Adapter Network Driver",
    .license     = "MIT",
    .url         = "https://github.com/purplek2/PurpleK2",
    .priority    = MOD_PRIO_LOW,
    .deps        = {"kernel", NULL}};

#define RTL8139_VENDOR_ID      0x10EC
#define RTL8139_DEVICE_ID      0x8139
#define RTL8139_RX_BUFFER_SIZE 0x2000 // 8KB + 16 bytes
#define RTL8139_TX_BUFFER_SIZE 0x1000 // 4KB per buffer
#define RTL8139_NUM_TX_BUFFERS 4

int current_buffer =
    1; // goes to 4. fuck you stupid round robin buffer system for transmit
size_t rx_offset = 0;

static rtl8139_t *rtl8139_device = NULL;

void rtl8139_interrupt_handler(void *regs) {
    UNUSED(regs);
    uint16_t status = _inw(rtl8139_device->mmio_addr + 0x3E);
    _outw(rtl8139_device->mmio_addr + 0x3E, 0x05);
    if (status & RTL8139_ISR_TOK) {
        switch (current_buffer) {
        case 1:
            current_buffer = 2;
            break;
        case 2:
            current_buffer = 3;
            break;
        case 3:
            current_buffer = 4;
            break;
        case 4:
            current_buffer = 1;
            break;
        default:
            current_buffer = 1;
            break;
        }
        debugf_debug("RTL8139: Sent Packet\n");
    }
    if (status & RTL8139_ISR_ROK) {
        // Received
        debugf_debug("RTL8139: Recieved Packet\n");
    }
}

#define CLEAR_BIT_MASK (1u << 13)

void rtl8139_write_packet(void *buffer, uint16_t len) {
    uint16_t actual_len = (len < 60) ? 60 : len;
    actual_len =
        actual_len & 0x0FFF; // keep only lower 12 bits (proper bit masking)

    if (actual_len > 1792) {
        actual_len = 1792; // Actually truncate if too large
    }

    uint16_t current_tsad = 0x20; // default
    uint16_t current_tsd  = 0x10;
    switch (current_buffer) {
    case 1:
        current_tsad = 0x20;
        current_tsd  = 0x10;
        break;
    case 2:
        current_tsad = 0x24;
        current_tsd  = 0x14;
        break;
    case 3:
        current_tsad = 0x28;
        current_tsd  = 0x18;
        break;
    case 4:
        current_tsad = 0x2C;
        current_tsd  = 0x1C;
        break;
    default:
        current_tsad = 0x20;
        current_tsd  = 0x10;
    }

    uint32_t tsd_val = actual_len;
    BIT_CLEAR(tsd_val, 13); // clear the own bit

    uint32_t phys = (uintptr_t)pmm_alloc_pages(1);
    map_phys_to_page((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), phys,
                     PHYS_TO_VIRTUAL(phys), PMLE_KERNEL_READ_WRITE);
    void *virt = (uint64_t *)(uintptr_t)PHYS_TO_VIRTUAL(phys);

    memcpy(virt, buffer, len);

    _outd(rtl8139_device->mmio_addr + current_tsad, (uint32_t)phys);
    _outd(rtl8139_device->mmio_addr + current_tsd, tsd_val);

    uint32_t tsd_readback = _ind(rtl8139_device->mmio_addr + current_tsd);
    debugf_debug("RTL8139: TSD written: 0x%08x, read back: 0x%08x\n", tsd_val,
                 tsd_readback);

    debugf_debug(
        "RTL8139: Send packet at physical address 0x%.16llx with size of %d\n",
        phys, actual_len);

    hex_dump_debug(buffer, actual_len);
}

void module_exit() {
    if (rtl8139_device) {
        debugf_debug("RTL8139: Module exiting, cleaning up...\n");

        kfree(rtl8139_device);
        rtl8139_device = NULL;
    }
}

void module_entry() {
    debugf("RTL8139: Module loading...\n");

    pci_device_t *pci_dev = get_pcihead();
    while (pci_dev) {
        if (pci_dev->vendor_id == RTL8139_VENDOR_ID &&
            pci_dev->device_id == RTL8139_DEVICE_ID) {
            break;
        }
        pci_dev = pci_dev->next;
    }

    if (!pci_dev) {
        debugf_warn("RTL8139 NIC not found!\n");
        return;
    }

    debugf_debug("RTL8139 NIC found at bus %u, device %u, function %u\n",
                 pci_dev->bus, pci_dev->device, pci_dev->function);

    rtl8139_device = kmalloc(sizeof(rtl8139_t));
    if (!rtl8139_device) {
        debugf_warn("RTL8139: Failed to allocate device structure\n");
        return;
    }
    memset(rtl8139_device, 0, sizeof(rtl8139_t));

    rtl8139_device->pci_device = pci_dev;

    uint16_t cmd = pci_config_read(pci_dev->bus, pci_dev->device,
                                   pci_dev->function, 0x04) &
                   0xFFFF;
    cmd |= (1 << 0) | (1 << 1) | (1 << 2);
    pci_config_write(pci_dev->bus, pci_dev->device, pci_dev->function, 0x04,
                     cmd);

    uint32_t io_base = pci_dev->bar[0];
    if (pci_dev->bar_type[0] == PCI_BAR_TYPE_PIO) {
        debugf_debug("RTL8139: Using Port IO!\n");
        rtl8139_device->io_space = 1;
    } else if (pci_dev->bar_type[0] == PCI_BAR_TYPE_MMIO) {
        debugf_debug("RTL8139: Using MMIO!\n");
        rtl8139_device->io_space = 0;
    } else {
        debugf_warn("Unknown BAR type at BAR0\n");
        return;
    }

    rtl8139_device->mmio_addr = io_base;

    if (!rtl8139_device->mmio_addr) {
        debugf_warn("RTL8139: Invalid BAR address\n");
        kfree(rtl8139_device);
        rtl8139_device = NULL;
        return;
    }

    debugf_debug("RTL8139: %s base address: 0x%x\n",
                 rtl8139_device->io_space ? "I/O" : "Memory",
                 rtl8139_device->mmio_addr);

    // turn it on!
    _outb(io_base + 0x52, 0x0);
    _outb(io_base + 0x37, 0x10);
    while ((_inb(io_base + 0x37) & 0x10) != 0) {
    }

    // alloc and set rx buffer
    rtl8139_device->rx_buffer =
        (uint64_t)(uintptr_t)kmalloc(RTL8139_RX_BUFFER_SIZE);
    _outd(io_base + 0x30, rtl8139_device->rx_buffer);

    // set imr and isr
    _outw(io_base + 0x3C, 0x0005);

    // configure RCR
    _outl(io_base + 0x44, 0xf | (1 << 7));

    irq_registerHandler(11, rtl8139_interrupt_handler);

    // enable rx and tx
    _outb(io_base + 0x37, 0x0C);

    // get mac address
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) {
        mac[i] = _inb(io_base + i);
    }

    debugf_debug("RTL8139: MAC Address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    const size_t pkt_len = sizeof(eth_header_t) + sizeof(arp_header_t);
    uint8_t *buf         = kmalloc(pkt_len);
    if (!buf) {
        debugf_warn("Failed to allocate memory for ARP request packet!\n");
        return;
    }

    uint32_t sender_ip = htonl(0xC0A80164);
    uint32_t target_ip = htonl(0xC0A80101);

    eth_header_t *eth = (eth_header_t *)buf;
    arp_header_t *arp = (arp_header_t *)(buf + sizeof(eth_header_t));
    memset(eth->dest, 0xFF, 6);
    memcpy(eth->src, mac, 6);
    eth->ethertype = htons(0x0806);

    arp->htype  = htons(1);          // Ethernet
    arp->ptype  = htons(0x0800);     // IPv4
    arp->hlen   = 6;                 // MAC length
    arp->plen   = 4;                 // IPv4 length
    arp->opcode = htons(1);          // ARP request
    memcpy(arp->sender_mac, mac, 6); // sender MAC
    arp->sender_ip = sender_ip;
    memset(arp->target_mac, 0x00, 6); // unknown target MAC
    arp->target_ip = target_ip;

    if (pkt_len < 60) {
        uint8_t *padded_buf = kmalloc(60);
        memset(padded_buf, 0, 60);        // Zero-fill
        memcpy(padded_buf, buf, pkt_len); // Copy your data
        rtl8139_write_packet(padded_buf, 60);
        kfree(padded_buf);
    } else {
        rtl8139_write_packet(buf, pkt_len);
    }

    debugf_debug("RTL8139: Module initialization completed successfully\n");
}