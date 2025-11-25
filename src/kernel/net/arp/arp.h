#ifndef ARP_H
#define ARP_H

#include <net/eth/ethernet.h>
#include <stdint.h>

typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[ETH_ALEN];
    uint32_t sender_ip;
    uint8_t target_mac[ETH_ALEN];
    uint32_t target_ip;
} __attribute__((packed)) arp_header_t;

// ARP opcodes
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

void arp_make_request(arp_header_t *arp, const uint8_t src_mac[6],
                      uint32_t src_ip, uint32_t target_ip);
void arp_make_reply(arp_header_t *arp, const uint8_t src_mac[6],
                    uint32_t src_ip, const uint8_t dest_mac[6],
                    uint32_t dest_ip);

#endif // ARP_H
