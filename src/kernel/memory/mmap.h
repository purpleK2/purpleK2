#ifndef MMAP_H
#define MMAP_H 1

#include <stddef.h>
#include <stdint.h>

/* POSIX mmap protection flags */
#define PROT_NONE   0x0
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4

/* POSIX mmap mapping flags */
#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS
#define MAP_NORESERVE   0x40
#define MAP_GROWSDOWN   0x100
#define MAP_STACK       0x200
#define MAP_POPULATE    0x400

/* mmap return value on failure */
#define MAP_FAILED ((void *)-1)

/* POSIX msync flags */
#define MS_ASYNC       0x1
#define MS_SYNC        0x2
#define MS_INVALIDATE  0x4

/* Page size */
#define MMAP_PAGE_SIZE 0x1000

/* User mmap region: 0x100000000 - 0x700000000000 */
#define MMAP_REGION_START 0x100000000ULL
#define MMAP_REGION_END   0x700000000000ULL

/* Forward declarations */
struct vmc_t;
struct vnode;
struct file_io;

/**
 * Core mmap implementation
 *
 * @param vmc     Virtual memory context for the process
 * @param addr    Hint address (or required if MAP_FIXED)
 * @param length  Length of the mapping in bytes
 * @param prot    Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
 * @param flags   Mapping flags (MAP_PRIVATE, MAP_SHARED, MAP_ANONYMOUS, etc.)
 * @param vnode   Vnode of the file to map (NULL for MAP_ANONYMOUS)
 * @param offset  Offset into file (ignored for MAP_ANONYMOUS)
 * @return        Pointer to mapped region, or MAP_FAILED on error
 */
void *do_mmap(struct vmc_t *vmc, void *addr, size_t length, int prot,
              int flags, struct vnode *vnode, size_t offset);

/**
 * Core munmap implementation
 *
 * @param addr    Address of the mapping to unmap
 * @param length  Length of the mapping to unmap
 * @return        0 on success, -1 on error
 */
int do_munmap(struct vmc_t *vmc, void *addr, size_t length);

/**
 * Core mprotect implementation
 *
 * @param addr    Address of the mapping to modify
 * @param length  Length of the region
 * @param prot    New protection flags
 * @return        0 on success, -1 on error
 */
int do_mprotect(struct vmc_t *vmc, void *addr, size_t length, int prot);

#endif /* MMAP_H */
