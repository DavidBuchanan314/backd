all: backd

backd: backd.c linux_syscall_support.h
	gcc backd.c -o backd -static -std=gnu99 -ffreestanding -nostdlib -Wall -Wextra -N -s -Os
