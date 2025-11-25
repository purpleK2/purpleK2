#ifndef IPI_H
#define IPI_H 1

#include <stdint.h>

#define IPI_VECTOR_HALT       0xF0
#define IPI_VECTOR_TLB_FLUSH  0xF1
#define IPI_VECTOR_RESCHEDULE 0xF2
#define IPI_VECTOR_TEST       0xF3

void register_ipi(void);

void ipi_send(uint8_t vector, uint8_t cpu);
void ipi_broadcast(uint8_t vector);
void ipi_self(uint8_t vector);

void tlb_shootdown(uint64_t virtual);

#endif // IPI_H