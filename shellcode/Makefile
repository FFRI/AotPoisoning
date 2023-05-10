TARGETS = nops.bin take_screen_shot.bin open_calc.bin execve.bin test_shellcode.out

all: ${TARGETS}

test_shellcode.out: test_shellcode.m
	clang -arch x86_64 -O3 $< -o $@

nops.bin:
	for i in {1..1000}; do echo -en "\x90" >> $@; done

.SUFFIXES: .asm .o
.asm.o:
	nasm -f macho64 $< -o $@

.SUFFIXES: .o .out
.o.out:
	ld -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem -o $@ $<

.SUFFIXES: .bin .out
.out.bin:
	$(eval entry_off := $(shell otool -l $< | grep entryoff | awk '{printf("0x%x\n", $$2)}'))
	$(eval func_size := $(shell size -mx $< | grep __text | awk '{print $$3}'))
	dd if=$< of=$@ skip=$(entry_off) bs=1 count=$(func_size)

clean:
	rm -f *.out *.bin *.o
