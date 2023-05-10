/*
 * (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
 */
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonCrypto.h>

void show_sha256(unsigned char* digest) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input executable>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char* path = argv[1];
    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file %s\n", path);
        return EXIT_FAILURE;
    }

    char fullpath [PATH_MAX+1] = {0};
    realpath(path, fullpath);
    printf("fullpath is %s\n", fullpath);

    struct stat st = {0};
    fstat(fileno(fp), &st);

    unsigned char* buffer = (unsigned char*)malloc(st.st_size);
    fread(buffer, st.st_size, 1, fp);

    struct mach_header_64* mh64 = (struct mach_header_64*)buffer;

    CC_SHA256_CTX ctx = {0};
    CC_SHA256_Init(&ctx);

    CC_SHA256_Update(&ctx, fullpath, strlen(fullpath));
    CC_SHA256_Update(&ctx, buffer, mh64->sizeofcmds + sizeof(struct mach_header_64));
    CC_SHA256_Update(&ctx, &st.st_uid, 4);
    CC_SHA256_Update(&ctx, &st.st_gid, 4);
    CC_SHA256_Update(&ctx, &st.st_mtimespec, 0x10);
    CC_SHA256_Update(&ctx, &st.st_ctimespec, 0x10);
    CC_SHA256_Update(&ctx, &st.st_birthtimespec, 0x10);
    CC_SHA256_Update(&ctx, &st.st_size, 8);

    unsigned char digest[32] = {0};
    CC_SHA256_Final(digest, &ctx);
    show_sha256(digest);
}
