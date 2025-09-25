#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>

#define ETH_ALEN 6

typedef struct {
    uint8_t dest[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t ethertype;
} __attribute__((packed)) eth_header_t;

// EtherTypes
#define ETH_TYPE_IP  0x0800
#define ETH_TYPE_ARP 0x0806

void eth_fill_header(eth_header_t *eth, const uint8_t dest[6],
                     const uint8_t src[6], uint16_t ethertype);
uint16_t eth_get_type(const eth_header_t *eth);

#endif // ETHERNET_H