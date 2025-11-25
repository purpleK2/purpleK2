# [OS Codename] roadmap

The current status and the future of this OS.
A build (`.iso` file) will be released every time a Milestone is completed. The various milestones _might_ be updated over the course of time.

## 1st Milestone

- [X] Bare bones (Limine and 64-bit kernel)

- [X] `printf` implementation (+ E9 port "debugging")

- [X] GDT
- [X] Interrupt handling (IDT, ISRs, IRQs)
- [X] PIC support
- PIT Driver
  - [X] Initialization
  - [X] PIT-supported sleep
- LAPIC/IOAPIC Initialization
  - [X] IRQ redirection to I/O APIC
  - [X] Interrupts work
  - [X] LAPIC timer init

- ACPI
  - [X] Get RSDP/RSDT information
  - [X] MADT (LAPIC initialization)
  - [ ] HPET
  - [ ] uACPI implementation

- Memory
  - [X] Get memory map
  - [X] Memory management
    - PMM
      - [X] Allocating/freeing page frames
    - VMM
      - [X] Paging
      - Mapping devices to memory
        - [X] LAPIC
        - [X] I/O APIC
      - [X] Actual VMM stuff (allocating, freeing virtual memory etc.)  
    - [X] Kernel heap (`kmalloc`, `kfree`)

- [X] Scheduler

- [Adaptive Driver Interface](https://github.com/project-adi)
  - [ ] Implementation
  - [ ] FS metalang

- [ ] PCIe support
- [ ] AHCI driver

- File systems
  - USTAR
    - [X] Basic initrd.img initialization
    - [X] File lookup
  - Virtual File System
    - [X] Design
    - [X] Implementation
  - RAMFS
    - [ ] (un)loading files in safe-to-use memory

  - [ ] ISO9660

- Hard drive setup:
  - [ ] FAT32 (boot partition)
  - [ ] EXTx  (system partition)

- [X] SMP

- [ ] Microkernel environment ([Eleanore Semaphore](https://wiki.osdev.org/Eleanore_Semaphore))
- [ ] Jump to userspace

## 2nd Milestone

- [ ] Syscalls
- [ ] ELF loading
- [ ] OS-specific toolchain
- [ ] UNIX/POSIX compatibility layer
    (if someone wants to port coreutils, bash, whatever)
- [ ] Basic shell
  - [ ] Configuration System (registry)
  - [ ] Enviroment Variables
  - [ ] Input and Ouput syscalls
- [ ] Video modes
  - [ ] Set better screen resolutions other than limine's default
  - [ ] (MAYBE) cool graphical stuff
  - [ ] Oh yeah, DOOM because we have to :3

## 3rd Milestone

- GUI
  - [ ] Obviously a lot of sketches and ideas
        (aiming to something coming out of the 1980s)
