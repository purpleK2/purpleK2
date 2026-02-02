#include "caps.h"

#include "caps.h"
#include "cpu.h"
#include <string.h>

void get_athwcap_bitmap(uint64_t bitmap[2]) {
    cpuid_ctx_t ctx;

    memset(bitmap, 0, 2 * sizeof(uint64_t));

    memset(&ctx, 0, sizeof(ctx));
    ctx.leaf = 0x1;
    if (_cpu_cpuid(&ctx) == 0) {
        bitmap[0] = (uint64_t)ctx.edx;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.leaf = 0x7;
    if (_cpu_cpuid(&ctx) == 0) {
        if (ctx.ebx & (1U << 0)) {
            bitmap[1] |= HWCAP2_FSGSBASE;
        }
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.leaf = 0x5;
    if (_cpu_cpuid(&ctx) == 0) {
        if (ctx.ecx & (1U << 0)) {
            bitmap[1] |= HWCAP2_RING3MWAIT;
        }
    }
}