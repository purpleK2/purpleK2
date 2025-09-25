#ifndef RTL8139_H
#define RTL8139_H

#include <stdint.h>

// Buffer sizes
#define RTL8139_TX_BUFFER_SIZE 2048
#define RTL8139_RX_BUFFER_SIZE (8192 + 16)

// Register offsets
#define RTL8139_MAC0    0x00 // MAC address registers (0x00-0x05)
#define RTL8139_CMD     0x37 // Command register
#define RTL8139_TCR     0x40 // Transmit Configuration Register
#define RTL8139_RCR     0x44 // Receive Configuration Register
#define RTL8139_RBSTART 0x30 // Receive Buffer Start Address
#define RTL8139_IMR     0x3C // Interrupt Mask Register
#define RTL8139_ISR     0x3E // Interrupt Status Register

// TX Descriptor registers
#define RTL8139_TSD0 0x10 // TX Status Descriptor 0
#define RTL8139_TSD1 0x14 // TX Status Descriptor 1
#define RTL8139_TSD2 0x18 // TX Status Descriptor 2
#define RTL8139_TSD3 0x1C // TX Status Descriptor 3

#define RTL8139_TSAD0 0x20 // TX Start Address Descriptor 0
#define RTL8139_TSAD1 0x24 // TX Start Address Descriptor 1
#define RTL8139_TSAD2 0x28 // TX Start Address Descriptor 2
#define RTL8139_TSAD3 0x2C // TX Start Address Descriptor 3

// Command register bits
#define RTL8139_CMD_RESET 0x10
#define RTL8139_CMD_RXE   0x08 // Receiver Enable
#define RTL8139_CMD_TXE   0x04 // Transmitter Enable

// TX Status register bits
#define RTL8139_TSD_OWN 0x2000 // Own bit (bit 13)
#define RTL8139_TSD_TOK 0x8000 // Transmit OK (bit 15)

// Configuration values
#define RTL8139_RCR_CONFIG 0x0000070A // Accept broadcast, multicast, unicast
#define RTL8139_TCR_CONFIG 0x03000700 // Normal transmit operation

// Function declarations
void rtl8139_init(uint32_t io_base, const uint8_t mac[6]);
int rtl8139_send_frame(const uint8_t *frame, uint16_t len);
int rtl8139_receive_frame(uint8_t *buffer, uint16_t buf_size,
                          uint16_t *out_len);
void rtl8139_send_arp_request(uint32_t my_ip, uint32_t target_ip);
void rtl8139_cleanup(void);

#endif // RTL8139_H