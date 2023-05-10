/*
 * (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
 */
// NOTE: based on https://www.exploit-db.com/shellcodes/46397
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

int (*sc)();

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Usage: %s <shellcode>\n", argv[0]);
		return EXIT_FAILURE;
	}

	FILE* fin = fopen(argv[1], "rb");
	struct stat buf;
	fstat(fileno(fin), &buf);

	uint8_t* buffer = malloc(buf.st_size * sizeof(char));
	fread(buffer, buf.st_size, 1, fin);

	void *ptr = mmap(0, buf.st_size, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	memcpy(ptr, buffer, buf.st_size);
	sc = ptr;

	free(buffer);

	puts("Running shellcode");
	sc();

	return EXIT_SUCCESS;
}
    
