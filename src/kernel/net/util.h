#ifndef NET_UTIL_H
#define NET_UTIL_H

#include <stdint.h>

static inline uint16_t htons(uint16_t x) {
    return __builtin_bswap16(x);
}
static inline uint16_t ntohs(uint16_t x) {
    return __builtin_bswap16(x);
}
static inline uint32_t htonl(uint32_t x) {
    return __builtin_bswap32(x);
}
static inline uint32_t ntohl(uint32_t x) {
    return __builtin_bswap32(x);
}

#endif // NET_UTIL_H