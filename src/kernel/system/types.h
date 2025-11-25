#ifndef TYPES_H
#define TYPES_H

#include <stdatomic.h>

// process management

typedef int pid_t;
typedef int ppid_t;

// user management

typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int id_t;

// file management

typedef unsigned int fd_t;

// locks
typedef atomic_flag lock_t;

#define LOCK_INIT                                                              \
    { 0 }

#endif // TYPES_H