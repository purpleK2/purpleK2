#include "math.h"

size_t log2(size_t num) {
    size_t i;

    for (i = 0; num / 2 != 0; i++) {
        num /= 2;
    }

    return i;
}