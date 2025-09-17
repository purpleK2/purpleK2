# Makefile for example_driver (kernel module / loadable driver)

# Compiler and flags
CC = gcc
CFLAGS = -O0 -g -Wall -Wextra -ffreestanding -fno-builtin \
         -fPIC -m64 -nostdlib -fno-pie \
         -I. \
         -I../../src \
         -I../../src/lib \
         -I../../src/kernel \
         -I../../src/kernel/system \
         -I../../src/kernel/acpi \
         -I../../src/arch/x86_64

# Target
TARGET = example_mod.km
SRC = driver.c

all: $(TARGET)

# Compile only, produce relocatable ELF object
$(TARGET):
	$(CC) $(CFLAGS) -c $(SRC) -o $(TARGET)

clean:
	rm -f *.o
