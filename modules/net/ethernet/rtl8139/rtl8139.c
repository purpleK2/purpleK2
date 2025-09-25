#include "rtl8139.h"
#include "memory/heap/kheap.h"
#include "net/arp/arp.h"
#include "net/eth/ethernet.h"
#include "net/eth/mac.h"
#include "net/util.h"
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t rtl_io_base;
static uint8_t rtl_mac[6];
static uint8_t *tx_buffer  = NULL;
static uint8_t *rx_buffer  = NULL;
static int current_tx_desc = 0;

// Helper function to get TX register offsets
static uint32_t get_tx_status_reg(int desc) {
    return RTL8139_TSD0 + (desc * 4);
}

static uint32_t get_tx_addr_reg(int desc) {
    return RTL8139_TSAD0 + (desc * 4);
}

// Initialize driver
void rtl8139_init(uint32_t io_base, const uint8_t mac[6]) {
    rtl_io_base = io_base;

    // Copy MAC address
    for (int i = 0; i < 6; i++) {
        rtl_mac[i] = mac[i];
    }

    kprintf("RTL8139: Starting initialization...\n");

    // Step 1: Reset the chip
    kprintf("RTL8139: Resetting device...\n");
    _outb(rtl_io_base + RTL8139_CMD, RTL8139_CMD_RESET);

    // Wait for reset to complete (should clear the reset bit)
    int reset_timeout = 1000000;
    while ((_inb(rtl_io_base + RTL8139_CMD) & RTL8139_CMD_RESET) &&
           reset_timeout--) {
        // Small delay
        for (volatile int i = 0; i < 100; i++)
            ;
    }

    if (reset_timeout <= 0) {
        kprintf_warn("RTL8139: Reset timeout!\n");
        return;
    }

    kprintf("RTL8139: Reset complete\n");

    // Step 2: Allocate buffers
    tx_buffer = kmalloc(RTL8139_TX_BUFFER_SIZE);
    if (!tx_buffer) {
        kprintf_warn("RTL8139: Failed to allocate TX buffer\n");
        return;
    }

    rx_buffer = kmalloc(RTL8139_RX_BUFFER_SIZE);
    if (!rx_buffer) {
        kprintf_warn("RTL8139: Failed to allocate RX buffer\n");
        kfree(tx_buffer);
        tx_buffer = NULL;
        return;
    }

    kprintf("RTL8139: Buffers allocated (TX: %p, RX: %p)\n", tx_buffer,
            rx_buffer);

    // Step 3: Configure receive buffer
    // RTL8139 needs RX buffer configured for proper operation
    _outl(rtl_io_base + RTL8139_RBSTART, (uint32_t)(uintptr_t)rx_buffer);
    kprintf("RTL8139: RX buffer configured\n");

    // Step 4: Configure receive configuration register
    _outl(rtl_io_base + RTL8139_RCR, RTL8139_RCR_CONFIG);
    kprintf("RTL8139: RCR configured\n");

    // Step 5: Configure transmit configuration register
    _outl(rtl_io_base + RTL8139_TCR, RTL8139_TCR_CONFIG);
    kprintf("RTL8139: TCR configured\n");

    // Step 6: Clear interrupt status
    _outw(rtl_io_base + RTL8139_ISR, 0xFFFF);

    // Step 7: Disable all interrupts for now
    _outw(rtl_io_base + RTL8139_IMR, 0x0000);

    // Step 8: Enable transmitter and receiver
    _outb(rtl_io_base + RTL8139_CMD, RTL8139_CMD_RXE | RTL8139_CMD_TXE);
    kprintf("RTL8139: TX and RX enabled\n");

    // Verify the command register
    uint8_t cmd_status = _inb(rtl_io_base + RTL8139_CMD);
    kprintf("RTL8139: CMD register = 0x%02x\n", cmd_status);

    kprintf("RTL8139: Initialization complete\n");
}

// Send raw Ethernet frame
int rtl8139_send_frame(const uint8_t *frame, uint16_t len) {
    if (!tx_buffer || !frame || len > RTL8139_TX_BUFFER_SIZE || len < 14) {
        kprintf_warn(
            "RTL8139: Invalid send parameters (len=%d, tx_buffer=%p)\n", len,
            tx_buffer);
        return -1;
    }

    // Ensure minimum frame size (pad if necessary)
    uint16_t send_len = len < 60 ? 60 : len;

    kprintf("RTL8139: Sending frame (len=%d, padded=%d)\n", len, send_len);

    // Copy frame to TX buffer
    memcpy(tx_buffer, frame, len);

    // Pad with zeros if necessary
    if (send_len > len) {
        memset(tx_buffer + len, 0, send_len - len);
    }

    // Get current TX descriptor registers
    uint32_t tx_addr_reg   = get_tx_addr_reg(current_tx_desc);
    uint32_t tx_status_reg = get_tx_status_reg(current_tx_desc);

    kprintf("RTL8139: Using TX desc %d (addr_reg=0x%x, status_reg=0x%x)\n",
            current_tx_desc, tx_addr_reg, tx_status_reg);

    // Set buffer address
    _outl(rtl_io_base + tx_addr_reg, (uint32_t)(uintptr_t)tx_buffer);

    // Set length and start transmission
    // Bit 13 (OWN) starts the transmission
    uint32_t tx_command = send_len | RTL8139_TSD_OWN;
    _outl(rtl_io_base + tx_status_reg, tx_command);

    kprintf("RTL8139: TX command written: 0x%x\n", tx_command);

    // Wait for transmission to complete
    int timeout = 1000000;
    uint32_t status;
    while (timeout--) {
        status = _inl(rtl_io_base + tx_status_reg);
        if (status & RTL8139_TSD_TOK) {
            kprintf("RTL8139: Transmission successful (status=0x%x)\n", status);
            break;
        }
        if (status & 0x4000) { // TUN (TX underrun) or other error bits
            kprintf_warn("RTL8139: Transmission error (status=0x%x)\n", status);
            break;
        }
        // Small delay
        for (volatile int i = 0; i < 10; i++)
            ;
    }

    if (timeout <= 0) {
        kprintf_warn("RTL8139: Transmission timeout (status=0x%x)\n",
                     _inl(rtl_io_base + tx_status_reg));
    }

    // Move to next TX descriptor
    current_tx_desc = (current_tx_desc + 1) % 4;

    return (timeout > 0) ? 0 : -1;
}

// Placeholder RX routine
int rtl8139_receive_frame(uint8_t *buffer, uint16_t buf_size,
                          uint16_t *out_len) {
    *out_len = 0;
    return 0; // Not implemented yet
}

// Send ARP request to target IP
void rtl8139_send_arp_request(uint32_t my_ip, uint32_t target_ip) {
    if (!tx_buffer) {
        kprintf_warn("RTL8139: Cannot send ARP - not initialized\n");
        return;
    }

    kprintf("RTL8139: Preparing ARP request\n");

    eth_header_t *eth = (eth_header_t *)tx_buffer;
    arp_header_t *arp = (arp_header_t *)(tx_buffer + sizeof(eth_header_t));

    // Ethernet header (broadcast)
    eth_fill_header(eth, mac_broadcast, rtl_mac, ETH_TYPE_ARP);

    // ARP payload
    arp_make_request(arp, rtl_mac, my_ip, target_ip);

    uint16_t frame_size = sizeof(eth_header_t) + sizeof(arp_header_t);
    kprintf("RTL8139: Sending ARP request (size=%d bytes)\n", frame_size);

    // Debug: print frame contents
    kprintf("RTL8139: Frame contents:\n");
    for (int i = 0; i < frame_size && i < 64; i++) {
        if (i % 16 == 0)
            kprintf("  %04x: ", i);
        kprintf("%02x ", tx_buffer[i]);
        if (i % 16 == 15)
            kprintf("\n");
    }
    if (frame_size % 16 != 0)
        kprintf("\n");

    int result = rtl8139_send_frame(tx_buffer, frame_size);
    if (result == 0) {
        kprintf("RTL8139: ARP request sent successfully\n");
    } else {
        kprintf_warn("RTL8139: Failed to send ARP request\n");
    }
}

// Cleanup function
void rtl8139_cleanup(void) {
    if (tx_buffer) {
        kfree(tx_buffer);
        tx_buffer = NULL;
    }
    if (rx_buffer) {
        kfree(rx_buffer);
        rx_buffer = NULL;
    }
}