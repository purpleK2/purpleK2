#include "arp.h"

#include <net/eth/mac.h>
#include <net/util.h>

void arp_make_request(arp_header_t *arp, const uint8_t src_mac[6],
                      uint32_t src_ip, uint32_t target_ip) {
    arp->htype  = htons(1);
    arp->ptype  = htons(0x0800);
    arp->hlen   = ETH_ALEN;
    arp->plen   = 4;
    arp->opcode = htons(ARP_OP_REQUEST);
    mac_copy(arp->sender_mac, src_mac);
    arp->sender_ip = htonl(src_ip);
    mac_zero(arp->target_mac);
    arp->target_ip = htonl(target_ip);
}

void arp_make_reply(arp_header_t *arp, const uint8_t src_mac[6],
                    uint32_t src_ip, const uint8_t dest_mac[6],
                    uint32_t dest_ip) {
    arp->htype  = htons(1);
    arp->ptype  = htons(0x0800);
    arp->hlen   = ETH_ALEN;
    arp->plen   = 4;
    arp->opcode = htons(ARP_OP_REPLY);
    mac_copy(arp->sender_mac, src_mac);
    arp->sender_ip = htonl(src_ip);
    mac_copy(arp->target_mac, dest_mac);
    arp->target_ip = htonl(dest_ip);
}
