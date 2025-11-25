#ifndef DUMP_H
#define DUMP_H

#include <stddef.h>
#include <stdint.h>

#define is_printable(c) ((c) >= 32 && (c) <= 126)

void hex_dump(const void *data, size_t size);

#endif // DUMP_H