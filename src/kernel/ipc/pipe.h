#pragma once
#include <fs/file_io.h>

#include "spinlock.h"
#include <stddef.h>
#include <stdint.h>

#define PIPE_BUFFER_SIZE 4096

typedef struct pipe {
    uint8_t buffer[PIPE_BUFFER_SIZE];
    size_t read_pos;
    size_t write_pos;
    size_t used;

    int readers;
    int writers;

    atomic_flag lock;
} pipe_t;

int pipe(fileio_t *fds[2]);
int pipe_read(fileio_t *fio, void *buf, size_t *size);
int pipe_write(fileio_t *fio, const void *buf, size_t *size);
int pipe_close(fileio_t *fio);
