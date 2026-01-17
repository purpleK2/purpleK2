.PHONY: all
all:
	clang \
		-target x86_64-unknown-none \
		-ffreestanding \
		-fno-stack-protector \
		-fPIE \
		-nostdlib \
		-Wl,-pie \
		-Wl,--entry=_start \
		-Wl,--no-dynamic-linker \
		-Wl,--build-id=none \
		-Wl,-z,max-page-size=0x1000 \
		-g -O0 \
		-o init.elf \
		main.c
