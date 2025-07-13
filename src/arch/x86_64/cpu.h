#ifndef CPU_H
#define CPU_H 1

#include <cpuid.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Vendor strings from CPUs.
#define CPUID_VENDOR_AMD "AuthenticAMD"
#define CPUID_VENDOR_AMD_OLD                                                   \
    "AMDisbetter!" // Early engineering samples of AMD K5 processor
#define CPUID_VENDOR_INTEL         "GenuineIntel"
#define CPUID_VENDOR_VIA           "VIA VIA VIA "
#define CPUID_VENDOR_TRANSMETA     "GenuineTMx86"
#define CPUID_VENDOR_TRANSMETA_OLD "TransmetaCPU"
#define CPUID_VENDOR_CYRIX         "CyrixInstead"
#define CPUID_VENDOR_CENTAUR       "CentaurHauls"
#define CPUID_VENDOR_NEXGEN        "NexGenDriven"
#define CPUID_VENDOR_UMC           "UMC UMC UMC "
#define CPUID_VENDOR_SIS           "SiS SiS SiS "
#define CPUID_VENDOR_NSC           "Geode by NSC"
#define CPUID_VENDOR_RISE          "RiseRiseRise"
#define CPUID_VENDOR_VORTEX        "Vortex86 SoC"
#define CPUID_VENDOR_AO486         "MiSTer AO486"
#define CPUID_VENDOR_AO486_OLD     "GenuineAO486"
#define CPUID_VENDOR_ZHAOXIN       "  Shanghai  "
#define CPUID_VENDOR_HYGON         "HygonGenuine"
#define CPUID_VENDOR_ELBRUS        "E2K MACHINE "

// Vendor strings from hypervisors.
#define CPUID_VENDOR_QEMU       "TCGTCGTCGTCG"
#define CPUID_VENDOR_KVM        " KVMKVMKVM  "
#define CPUID_VENDOR_VMWARE     "VMwareVMware"
#define CPUID_VENDOR_VIRTUALBOX "VBoxVBoxVBox"
#define CPUID_VENDOR_XEN        "XenVMMXenVMM"
#define CPUID_VENDOR_HYPERV     "Microsoft Hv"
#define CPUID_VENDOR_PARALLELS  " prl hyperv "
#define CPUID_VENDOR_PARALLELS_ALT                                             \
    " lrpepyh vr " // Sometimes Parallels incorrectly encodes "prl hyperv" as
                   // "lrpepyh vr" due to an endianness mismatch.
#define CPUID_VENDOR_BHYVE "bhyve bhyve "
#define CPUID_VENDOR_QNX   " QNXQVMBSQG "

#define CPUID_FEAT_ECX_SSE3       1 << 0
#define CPUID_FEAT_ECX_PCLMUL     1 << 1
#define CPUID_FEAT_ECX_DTES64     1 << 2
#define CPUID_FEAT_ECX_MONITOR    1 << 3
#define CPUID_FEAT_ECX_DS_CPL     1 << 4
#define CPUID_FEAT_ECX_VMX        1 << 5
#define CPUID_FEAT_ECX_SMX        1 << 6
#define CPUID_FEAT_ECX_EST        1 << 7
#define CPUID_FEAT_ECX_TM2        1 << 8
#define CPUID_FEAT_ECX_SSSE3      1 << 9
#define CPUID_FEAT_ECX_CID        1 << 10
#define CPUID_FEAT_ECX_SDBG       1 << 11
#define CPUID_FEAT_ECX_FMA        1 << 12
#define CPUID_FEAT_ECX_CX16       1 << 13
#define CPUID_FEAT_ECX_XTPR       1 << 14
#define CPUID_FEAT_ECX_PDCM       1 << 15
#define CPUID_FEAT_ECX_PCID       1 << 17
#define CPUID_FEAT_ECX_DCA        1 << 18
#define CPUID_FEAT_ECX_SSE4_1     1 << 19
#define CPUID_FEAT_ECX_SSE4_2     1 << 20
#define CPUID_FEAT_ECX_X2APIC     1 << 21
#define CPUID_FEAT_ECX_MOVBE      1 << 22
#define CPUID_FEAT_ECX_POPCNT     1 << 23
#define CPUID_FEAT_ECX_TSC        1 << 24
#define CPUID_FEAT_ECX_AES        1 << 25
#define CPUID_FEAT_ECX_XSAVE      1 << 26
#define CPUID_FEAT_ECX_OSXSAVE    1 << 27
#define CPUID_FEAT_ECX_AVX        1 << 28
#define CPUID_FEAT_ECX_F16C       1 << 29
#define CPUID_FEAT_ECX_RDRAND     1 << 30
#define CPUID_FEAT_ECX_HYPERVISOR 1 << 31

#define CPUID_FEAT_EDX_FPU     1 << 0
#define CPUID_FEAT_EDX_VME     1 << 1
#define CPUID_FEAT_EDX_DE      1 << 2
#define CPUID_FEAT_EDX_PSE     1 << 3
#define CPUID_FEAT_EDX_TSC     1 << 4
#define CPUID_FEAT_EDX_MSR     1 << 5
#define CPUID_FEAT_EDX_PAE     1 << 6
#define CPUID_FEAT_EDX_MCE     1 << 7
#define CPUID_FEAT_EDX_CX8     1 << 8
#define CPUID_FEAT_EDX_APIC    1 << 9
#define CPUID_FEAT_EDX_SEP     1 << 11
#define CPUID_FEAT_EDX_MTRR    1 << 12
#define CPUID_FEAT_EDX_PGE     1 << 13
#define CPUID_FEAT_EDX_MCA     1 << 14
#define CPUID_FEAT_EDX_CMOV    1 << 15
#define CPUID_FEAT_EDX_PAT     1 << 16
#define CPUID_FEAT_EDX_PSE36   1 << 17
#define CPUID_FEAT_EDX_PSN     1 << 18
#define CPUID_FEAT_EDX_CLFLUSH 1 << 19
#define CPUID_FEAT_EDX_DS      1 << 21
#define CPUID_FEAT_EDX_ACPI    1 << 22
#define CPUID_FEAT_EDX_MMX     1 << 23
#define CPUID_FEAT_EDX_FXSR    1 << 24
#define CPUID_FEAT_EDX_SSE     1 << 25
#define CPUID_FEAT_EDX_SSE2    1 << 26
#define CPUID_FEAT_EDX_SS      1 << 27
#define CPUID_FEAT_EDX_HTT     1 << 28
#define CPUID_FEAT_EDX_TM      1 << 29
#define CPUID_FEAT_EDX_IA64    1 << 30
#define CPUID_FEAT_EDX_PBE     1 << 31

// gets a value from a CRX register
// by
// https://github.com/Tix3Dev/apoptOS/blob/370fd34a6d3c87a9d1a16d1a2ec072bd1836ba6c/src/kernel/utility/utils.h#L26
#define cpu_get_cr(reg)                                                        \
    ({                                                                         \
        uint64_t val = 0;                                                      \
        asm volatile("mov %%cr" #reg ", %0" : "=r"(val));                      \
        val;                                                                   \
    })

bool check_pae();
bool check_msr();
bool check_tsc();
bool check_apic();
bool check_x2apic();
bool check_sse();
bool check_fpu();
bool check_sse2();
bool check_fxsr();

typedef struct cpuid_ctx {
    uint32_t leaf;

    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuid_ctx_t;

const char *get_cpu_vendor();
int get_cpu_name(char *out);

// check if we're running on a hypervisor
bool check_hypervisor();
// get hypervisor name
int get_hypervisor(char *out);

// returns the value from the requested MSR
extern uint64_t _cpu_get_msr(uint32_t msr);
// sets a MSR to the given value
extern void _cpu_set_msr(uint32_t msr, uint64_t value);

extern int _cpu_cpuid(cpuid_ctx_t *ctx);

// returns the value of RFLAGS register
uint64_t _get_cpu_flags();
void _set_cpu_flags(uint64_t flags); // uhmmm apparently uACPI wants this :/

void cpu_reg_write(uint32_t *reg, uint32_t value);
uint32_t cpu_reg_read(uint32_t *reg);

#endif
