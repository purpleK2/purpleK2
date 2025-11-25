/*
        Generic macros for multiple cases
*/

#ifndef UTIL_H
#define UTIL_H 1

#define stringify(sumthin) #sumthin

// Alignment macros
// from
// https://github.com/Tix3Dev/apoptOS/blob/370fd34a6d3c87a9d1a16d1a2ec072bd1836ba6c/src/kernel/memory/mem.h#L36
#define ROUND_DOWN(n, a) ((n) & ~((a) - 1))
#define ROUND_UP(n, a)   (((n) + (a) - 1) & ~((a) - 1))

#define FLAG_SET(x, flag)   x |= (flag)
#define FLAG_UNSET(x, flag) x &= ~(flag)

#define BIT_GET(v, s) (((v) >> (s)) & 0b1)

#define UNUSED(x) (void)x

int oct2bin(const char *str, int size);

#endif