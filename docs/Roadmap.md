# [OS Codename] roadmap

The current status and the future of this OS.
A build (`.iso` file) will be released every time a Milestone is completed. The various milestones _might_ be updated over the course of time.

## 3rd Milestone

- GUI
  - [ ] lots of sketches and ideas


## 2nd Milestone

- More filesystem stuff
  - [ ] ISO9660
- Hard drive setup:
    - [ ] FAT32 (boot partition)
    - [ ] EXTx  (system partition)

- [ ] Syscalls
- [ ] ELF loading
- [ ] OS-specific toolchain
- [ ] UNIX/POSIX compatibility layer
    (if someone wants to port `coreutils`, `bash`, whatever)

- [ ] Basic shell
  - [ ] Configuration System (registry)
  - [ ] Enviroment Variables
  - [ ] Input and Ouput syscalls

- [ ] Video modes
  - [ ] Set better screen resolutions other than limine's default
  - [ ] Some kind of graphics API
  - [ ] Oh yeah, DOOM because we have to :3


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
  - uACPI implementation
    - [X] ACPI tables parsing
    - [ ] the cool SSDT stuff
  - [X] Get RSDP/RSDT
  - [X] MADT (LAPIC initialization)
  - [X] HPET
  - [X] MCFG (PCIe devices parsing)

- Memory
  - [X] Get memory map
  - [X] Memory management
    - PMM
      - [X] Allocating/freeing page frames
    - VMM
      - [X] Paging
      - [X] Actual VMM stuff (allocating, freeing virtual memory regions)
    - [X] Kernel heap (`kmalloc`, `kfree`)

- ~~[Adaptive Driver Interface](https://github.com/project-adi)~~ SCRAPPED

- PCI/PCIe support
  - [X] PCI(e) devices parsing
  - [ ] API for drivers

- [ ] AHCI driver
  (we can then read from the disk 🔥)

- File systems
  - ~~USTAR~~ CPIO
    - [X] Initial initrd creation
    - [X] File lookup
  - RAMFS
    - [ ] Base structures
    - [ ] File I/O (`open`, `read`, ...)
  - Virtual File System
    - [X] (Re)Design
    - [ ] Initialization
    - [ ] File I/O (`fopen`, `fread`)

- [ ] Scheduler
  - [ ] with threads and stuff
- [ ] SMP

- [ ] Jump to userspace
