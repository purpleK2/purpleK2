#ifndef IP_H
#define IP_H

#include <stdint.h>

static inline int ip_equal(uint32_t ip1, uint32_t ip2) {
    return ip1 == ip2;
}

#endif // IP_H