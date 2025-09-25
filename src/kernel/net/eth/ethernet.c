#include "ethernet.h"

#include <net/eth/mac.h>
#include <net/util.h>

void eth_fill_header(eth_header_t *eth, const uint8_t dest[6],
                     const uint8_t src[6], uint16_t ethertype) {
    mac_copy(eth->dest, dest);
    mac_copy(eth->src, src);
    eth->ethertype = htons(ethertype);
}

uint16_t eth_get_type(const eth_header_t *eth) {
    return ntohs(eth->ethertype);
}
