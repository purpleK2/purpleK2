#include "cpu.h"

#include <string.h>

bool check_pae() {
    uint64_t cr4 = cpu_get_cr(4);

    return cr4 & (1 << 5);
}

bool check_msr() {
    static uint32_t eax, unused, edx;
    __get_cpuid(1, &eax, &unused, &unused, &edx);
    return edx & CPUID_FEAT_EDX_MSR;
}

bool check_apic() {
    uint32_t eax, edx, unused;
    __get_cpuid(1, &eax, &unused, &unused, &edx);
    return edx & CPUID_FEAT_EDX_APIC;
}

bool check_tsc() {
    uint32_t edx, unused;
    __get_cpuid(0x01, &unused, &unused, &unused, &edx);
    return (edx & (1 << 4)) ? 1 : 0;
}

bool check_x2apic() {
    uint32_t eax, edx, unused;
    __get_cpuid(1, &eax, &unused, &unused, &edx);
    return edx & CPUID_FEAT_ECX_X2APIC;
}

bool check_fpu() {
    uint32_t eax, edx, unused;
    __get_cpuid(1, &eax, &unused, &unused, &edx);
    return edx & CPUID_FEAT_EDX_FPU;
}

bool check_sse() {
    uint32_t eax, edx, unused;
    __get_cpuid(1, &eax, &unused, &unused, &edx);
    return edx & CPUID_FEAT_EDX_SSE;
}

bool check_sse2() {
    uint32_t eax, edx, unused;
    __get_cpuid(1, &eax, &unused, &unused, &edx);
    return edx & CPUID_FEAT_EDX_SSE2;
}

bool check_fxsr() {
    uint32_t eax, edx, unused;
    __get_cpuid(1, &eax, &unused, &unused, &edx);
    return edx & CPUID_FEAT_EDX_FXSR;
}

void cpu_reg_write(uint32_t *reg, uint32_t value) {
    *reg = value;
}

uint32_t cpu_reg_read(uint32_t *reg) {
    return *reg;
}

bool check_hypervisor() {
    unsigned int data[4];

    __get_cpuid(0x1, &data[0], &data[1], &data[2], &data[3]);

    return (data[2] >> 31) & 0x1;
}

// @note `out` parameter must be AT LEAST 13 bytes
int get_hypervisor(char *out) {
    if (!out) {
        return -1;
    }

    if (!check_hypervisor()) {
        return -2;
    }

    cpuid_ctx_t hypervisor_ctx = {
        .leaf = 0x40000000, .eax = 0, .ebx = 0, .ecx = 0, .edx = 0};

    _cpu_cpuid(&hypervisor_ctx);

    memcpy(out, &hypervisor_ctx.ebx, 12);
    out[12] = '\0'; // Null-terminate the string

    return 0;
}

int get_cpu_vendor(char *out) {
    if (!out) {
        return -1;
    }
    memset(out, 0, 13);

    cpuid_ctx_t ctx = {.leaf = 0};

    if (_cpu_cpuid(&ctx) != 0) {
        strcpy(out, "UNKNOWN");
        return 1;
    }

    memcpy(out, &ctx.ebx, 4);
    memcpy(&out[4], &ctx.edx, 4);
    memcpy(&out[7], &ctx.ecx, 4);
    out[12] = '\0';
    return 0;
}

// @param out output string to save the result in. MUST BE AT LEAST 50 BYTES
// LONG
int get_cpu_name(char *out) {
    if (!out) {
        return -1;
    }
    memset(out, 0, 49);

    cpuid_ctx_t ctx;
    for (int i = 0; i < 3; i++) {
        ctx.leaf = 0x80000002 + i;
        _cpu_cpuid(&ctx);

        memcpy(out + i * 16, &ctx.eax, 16);
    }

    return 0;
}
