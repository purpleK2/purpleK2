/*
        Generic macros for multiple cases
*/

#ifndef UTIL_H
#define UTIL_H 1

#define GET_BIT(num, bit)    (((num) >> (bit)) & 0x1u)
#define SET_BIT(num, bit)    ((num) |= (1u << (bit)))
#define CLEAR_BIT(num, bit)  ((num) &= ~(1u << (bit)))
#define TOGGLE_BIT(num, bit) ((num) ^= (1u << (bit)))

int oct2bin(const char *str, int size);

#endif