#ifndef MAC_H
#define MAC_H

#include <stdint.h>

static inline int mac_equal(const uint8_t a[6], const uint8_t b[6]) {
    for (int i = 0; i < 6; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

static inline void mac_copy(uint8_t dest[6], const uint8_t src[6]) {
    for (int i = 0; i < 6; i++)
        dest[i] = src[i];
}

static inline void mac_zero(uint8_t mac[6]) {
    for (int i = 0; i < 6; i++)
        mac[i] = 0;
}

static const uint8_t mac_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#endif // MAC_H