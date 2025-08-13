symbol-file build/kernel.elf
set disassembly-flavor intel
set output-radix 16
target remote | qemu-system-x86_64 -S -gdb stdio -debugcon file:qemu_gdb.log -m 64M -hda kernel-v0.hdd
