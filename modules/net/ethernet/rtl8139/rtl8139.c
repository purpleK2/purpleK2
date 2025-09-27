#include "rtl8139.h"
#include "memory/heap/kheap.h"
#include "memory/pmm/pmm.h"
#include "net/arp/arp.h"
#include "net/eth/ethernet.h"
#include "net/eth/mac.h"
#include "net/util.h"
#include "paging/paging.h"
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static struct rtl8139_state {
    uint32_t io_base;
    uint8_t mac[6];
    uint8_t *tx_buffer;
    uint8_t *rx_buffer;
    uint32_t tx_phys;
    uint32_t rx_phys;
    int current_tx_desc;
    bool initialized;
} rtl;

#define mb()  __asm__ __volatile__("mfence" ::: "memory")
#define wmb() __asm__ __volatile__("sfence" ::: "memory")
#define rmb() __asm__ __volatile__("lfence" ::: "memory")

static inline uint32_t get_tx_status_reg(int desc) {
    return RTL8139_TSD0 + (desc * 4);
}

static inline uint32_t get_tx_addr_reg(int desc) {
    return RTL8139_TSAD0 + (desc * 4);
}

static void *alloc_dma_buffer(size_t pages, uint32_t *phys) {
    void *virt = pages == 1 ? pmm_alloc_page() : pmm_alloc_pages(pages);
    if (!virt)
        return NULL;

    uintptr_t phys_addr = (uintptr_t)virt;
    if (phys_addr > 0xFFFFFFFFUL) {
        pmm_free(virt, pages);
        return NULL;
    }

    if (pages == 1) {
        map_phys_to_page((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), phys_addr,
                         phys_addr,
                         PMLE_KERNEL_READ_WRITE | PMLE_NOT_EXECUTABLE);
    } else {
        map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), phys_addr,
                           phys_addr, pages * PAGE_SIZE,
                           PMLE_KERNEL_READ_WRITE | PMLE_NOT_EXECUTABLE);
    }

    *phys = (uint32_t)phys_addr;
    memset(virt, 0, pages * PAGE_SIZE);
    return virt;
}

static bool wait_ready(uint32_t reg, uint32_t mask, uint32_t expected,
                       int timeout) {
    while (timeout-- > 0) {
        uint32_t val =
            (reg < 0x100) ? _inb(rtl.io_base + reg) : _inl(rtl.io_base + reg);
        if ((val & mask) == expected)
            return true;
        for (volatile int i = 0; i < 10; i++)
            ;
    }
    return false;
}

void rtl8139_init(uint32_t io_base, const uint8_t mac[6]) {
    memset(&rtl, 0, sizeof(rtl));
    rtl.io_base = io_base;
    memcpy(rtl.mac, mac, 6);

    debugf("RTL8139: Starting initialization...\n");

    uint16_t vendor = _inw(io_base) | (_inw(io_base + 2) << 16);
    if ((vendor & 0xFFFF) != 0x10EC) {
        debugf_warn("RTL8139: Invalid vendor ID 0x%04x\n", vendor & 0xFFFF);
        return;
    }

    debugf("RTL8139: Resetting device...\n");
    _outb(io_base + RTL8139_CMD, RTL8139_CMD_RESET);
    if (!wait_ready(RTL8139_CMD, RTL8139_CMD_RESET, 0, 1000000)) {
        debugf_warn("RTL8139: Reset timeout!\n");
        return;
    }
    debugf("RTL8139: Reset complete\n");

    rtl.tx_buffer = alloc_dma_buffer(1, &rtl.tx_phys);
    if (!rtl.tx_buffer) {
        debugf_warn("RTL8139: Failed to allocate TX buffer\n");
        return;
    }

    rtl.rx_buffer = alloc_dma_buffer(3, &rtl.rx_phys);
    if (!rtl.rx_buffer) {
        debugf_warn("RTL8139: Failed to allocate RX buffer\n");
        pmm_free(rtl.tx_buffer, 1);
        rtl.tx_buffer = NULL;
        return;
    }

    debugf("RTL8139: Buffers allocated (TX: %p, RX: %p)\n", rtl.tx_buffer,
           rtl.rx_buffer);

    _outl(io_base + RTL8139_RBSTART, rtl.rx_phys);
    debugf("RTL8139: RX buffer configured\n");
    wmb();

    _outl(io_base + RTL8139_RCR, RTL8139_RCR_CONFIG);
    debugf("RTL8139: RCR configured\n");

    _outl(io_base + RTL8139_TCR, RTL8139_TCR_CONFIG);
    debugf("RTL8139: TCR configured\n");

    _outw(io_base + RTL8139_ISR, 0xFFFF);
    _outw(io_base + RTL8139_IMR, 0x0000);

    _outb(io_base + RTL8139_CMD, RTL8139_CMD_RXE | RTL8139_CMD_TXE);
    debugf("RTL8139: TX and RX enabled\n");

    uint8_t cmd_status = _inb(io_base + RTL8139_CMD);
    debugf("RTL8139: CMD register = 0x%02x\n", cmd_status);

    if ((cmd_status & (RTL8139_CMD_RXE | RTL8139_CMD_TXE)) !=
        (RTL8139_CMD_RXE | RTL8139_CMD_TXE)) {
        debugf_warn("RTL8139: Failed to enable TX/RX\n");
        rtl8139_cleanup();
        return;
    }

    rtl.initialized = true;
    debugf("RTL8139: Initialization complete\n");
}

int rtl8139_send_frame(const uint8_t *frame, uint16_t len) {
    if (!rtl.initialized || !frame || len > RTL8139_TX_BUFFER_SIZE ||
        len < 14) {
        debugf_warn("RTL8139: Invalid send parameters (len=%d, tx_buffer=%p)\n",
                    len, rtl.tx_buffer);
        return -1;
    }

    uint16_t send_len = len < 60 ? 60 : len;
    debugf("RTL8139: Sending frame (len=%d, padded=%d)\n", len, send_len);

    uint32_t tx_addr_reg   = get_tx_addr_reg(rtl.current_tx_desc);
    uint32_t tx_status_reg = get_tx_status_reg(rtl.current_tx_desc);

    uint32_t status = _inl(rtl.io_base + tx_status_reg);
    if (status & RTL8139_TSD_OWN) {
        debugf_warn("RTL8139: TX descriptor %d busy (status=0x%x)\n",
                    rtl.current_tx_desc, status);
        return -1;
    }

    debugf("RTL8139: Using TX desc %d (addr_reg=0x%x, status_reg=0x%x)\n",
           rtl.current_tx_desc, tx_addr_reg, tx_status_reg);

    memcpy(rtl.tx_buffer, frame, len);
    if (send_len > len) {
        memset(rtl.tx_buffer + len, 0, send_len - len);
    }
    wmb();

    _outl(rtl.io_base + tx_addr_reg, rtl.tx_phys);
    uint32_t tx_command = send_len | RTL8139_TSD_OWN;
    _outl(rtl.io_base + tx_status_reg, tx_command);
    wmb();

    debugf("RTL8139: TX command written: 0x%x\n", tx_command);

    if (!wait_ready(tx_status_reg, RTL8139_TSD_OWN, 0, 1000000)) {
        debugf_warn("RTL8139: Transmission timeout (status=0x%x)\n",
                    _inl(rtl.io_base + tx_status_reg));
        return -1;
    }

    status = _inl(rtl.io_base + tx_status_reg);
    if (status & RTL8139_TSD_TOK) {
        debugf("RTL8139: Transmission successful (status=0x%x)\n", status);
    } else if (status & 0x4000) {
        debugf_warn("RTL8139: Transmission error (status=0x%x)\n", status);
        return -1;
    }

    rtl.current_tx_desc = (rtl.current_tx_desc + 1) % 4;
    return 0;
}

int rtl8139_receive_frame(uint8_t *buffer, uint16_t buf_size,
                          uint16_t *out_len) {
    *out_len = 0;
    return 0;
}

void rtl8139_send_arp_request(uint32_t my_ip, uint32_t target_ip) {
    if (!rtl.tx_buffer) {
        debugf_warn("RTL8139: Cannot send ARP - not initialized\n");
        return;
    }

    debugf("RTL8139: Preparing ARP request\n");

    eth_header_t *eth = (eth_header_t *)rtl.tx_buffer;
    arp_header_t *arp = (arp_header_t *)(rtl.tx_buffer + sizeof(eth_header_t));

    eth_fill_header(eth, mac_broadcast, rtl.mac, ETH_TYPE_ARP);
    arp_make_request(arp, rtl.mac, my_ip, target_ip);

    uint16_t frame_size = sizeof(eth_header_t) + sizeof(arp_header_t);
    debugf("RTL8139: Sending ARP request (size=%d bytes)\n", frame_size);

    debugf("RTL8139: Frame contents:\n");
    for (int i = 0; i < frame_size && i < 64; i++) {
        if (i % 16 == 0)
            debugf("  %04x: ", i);
        debugf("%02x ", rtl.tx_buffer[i]);
        if (i % 16 == 15)
            debugf("\n");
    }
    if (frame_size % 16 != 0)
        debugf("\n");

    int result = rtl8139_send_frame(rtl.tx_buffer, frame_size);
    if (result == 0) {
        debugf("RTL8139: ARP request sent successfully\n");
    } else {
        debugf_warn("RTL8139: Failed to send ARP request\n");
    }
}

void rtl8139_cleanup(void) {
    if (!rtl.initialized)
        return;

    _outb(rtl.io_base + RTL8139_CMD, 0);
    _outw(rtl.io_base + RTL8139_IMR, 0);
    _outw(rtl.io_base + RTL8139_ISR, 0xFFFF);

    if (rtl.tx_buffer) {
        pmm_free(rtl.tx_buffer, 1);
        rtl.tx_buffer = NULL;
    }

    if (rtl.rx_buffer) {
        pmm_free(rtl.rx_buffer, 3);
        rtl.rx_buffer = NULL;
    }

    memset(&rtl, 0, sizeof(rtl));
}