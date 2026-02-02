#ifndef CAPS_H
#define CAPS_H 1

#include <stdint.h>

#define HWCAP_FPU       (1UL << 0)   // Onboard FPU
#define HWCAP_VME       (1UL << 1)   // Virtual Mode Extensions
#define HWCAP_DE        (1UL << 2)   // Debugging Extensions
#define HWCAP_PSE       (1UL << 3)   // Page Size Extensions
#define HWCAP_TSC       (1UL << 4)   // Time Stamp Counter
#define HWCAP_MSR       (1UL << 5)   // Model-Specific Registers
#define HWCAP_PAE       (1UL << 6)   // Physical Address Extensions
#define HWCAP_MCE       (1UL << 7)   // Machine Check Exception
#define HWCAP_CX8       (1UL << 8)   // CMPXCHG8 instruction
#define HWCAP_APIC      (1UL << 9)   // Onboard APIC
#define HWCAP_SEP       (1UL << 11)  // SYSENTER/SYSEXIT
#define HWCAP_MTRR      (1UL << 12)  // Memory Type Range Registers
#define HWCAP_PGE       (1UL << 13)  // Page Global Enable
#define HWCAP_MCA       (1UL << 14)  // Machine Check Architecture
#define HWCAP_CMOV      (1UL << 15)  // CMOV instructions (plus FCMOVcc, FCOMI with FPU)
#define HWCAP_PAT       (1UL << 16)  // Page Attribute Table
#define HWCAP_PSE36     (1UL << 17)  // 36-bit PSEs
#define HWCAP_PSN       (1UL << 18)  // Processor serial number
#define HWCAP_CLFLUSH   (1UL << 19)  // CLFLUSH instruction
#define HWCAP_DS        (1UL << 21)  // Debug Store
#define HWCAP_ACPI      (1UL << 22)  // ACPI via MSR
#define HWCAP_MMX       (1UL << 23)  // Multimedia Extensions
#define HWCAP_FXSR      (1UL << 24)  // FXSAVE/FXRSTOR, CR4.OSFXSR
#define HWCAP_SSE       (1UL << 25)  // SSE
#define HWCAP_SSE2      (1UL << 26)  // SSE2
#define HWCAP_SS        (1UL << 27)  // CPU self snoop
#define HWCAP_HTT       (1UL << 28)  // Hyper-Threading
#define HWCAP_TM        (1UL << 29)  // Automatic clock control
#define HWCAP_IA64      (1UL << 30)  // IA-64 processor
#define HWCAP_PBE       (1UL << 31)  // Pending Break Enable

#define HWCAP2_RING3MWAIT (1UL << 0) // MONITOR/MWAIT enabled in Ring 3
#define HWCAP2_FSGSBASE   (1UL << 1) // Kernel allows FSGSBASE instructions available in Ring 3

void get_athwcap_bitmap(uint64_t bitmap[2]);

#endif