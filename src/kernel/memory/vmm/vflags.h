/*
    I was going insane after some redefinition shenanigans

    Just some flags needed for abstraction between paging and VMM

    (C) RepubblicaTech 2025
*/

#ifndef VFLAGS_H
#define VFLAGS_H 1

// VMO flags
#define VMO_PRESENT (1 << 0)
#define VMO_RW      (1 << 1)
#define VMO_USR     (1 << 2)
#define VMO_NX      (1 << 3)

// this flag get's set when the VMO gets allocated
// YOU SHOULD NOT USE THIS
// (we'll check for it anyway)
#define VMO_ALLOCATED (1 << 8)

// VMO "macro"flags
#define VMO_KERNEL    VMO_PRESENT
#define VMO_KERNEL_RW VMO_RW | VMO_KERNEL
#define VMO_USER      VMO_PRESENT | VMO_USR
#define VMO_USER_RW   VMO_USER | VMO_RW

#endif