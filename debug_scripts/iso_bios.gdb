symbol-file build/kernel.elf
set disassembly-flavor intel
set output-radix 16
target remote | qemu-system-x86_64 -S -gdb stdio -debugcon file:qemu_gdb.log -M q35 -m 2G -smp 2 -netdev tap,id=net0,ifname=tap0,script=no,downscript=no -device rtl8139,netdev=net0,mac=52:54:00:12:34:56 -cdrom kernel-v0.iso
