.PHONY: all
all:
	clang \
  		-target x86_64-unknown-none \
  		-ffreestanding \
  		-fno-stack-protector \
  		-fno-pic \
  		-nostdlib \
  		-static \
  		-Wl,--entry=_start \
  		-Wl,--no-dynamic-linker \
  		-Wl,--build-id=none \
  		-o sched_test.elf \
  		main.c
