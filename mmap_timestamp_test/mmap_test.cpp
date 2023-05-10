/*
 * (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
 */
#include <iostream>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

void show_timestamps(int fd) {
    struct stat buf {};
    fstat(fd, &buf);
    printf("mtime:  %lx %lx\n", buf.st_mtimespec.tv_sec, buf.st_mtimespec.tv_nsec);
    printf("ctime:  %lx %lx\n", buf.st_ctimespec.tv_sec, buf.st_ctimespec.tv_nsec);
    printf("crtime: %lx %lx\n", buf.st_birthtimespec.tv_sec, buf.st_birthtimespec.tv_nsec);
    printf("=========================\n");
}

int main() {
    unlink("testfile");
    int fd = open("testfile", O_RDWR | O_CREAT | O_EXCL);

    std::puts("Write data to testfile");
    const char* buf = "Hello World!";
    write(fd, buf, strlen(buf));
    show_timestamps(fd);

    std::puts("Change data via mmap & unmap");
    char* mbuf = (char*)mmap(NULL, strlen(buf), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    mbuf[0]++;
    munmap(mbuf, strlen(buf));
    show_timestamps(fd);

    std::puts("Change data via mmap & munmap & msync");
    mbuf = (char*)mmap(NULL, strlen(buf), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    mbuf[0]++;
    msync(mbuf, strlen(buf), MS_SYNC);
    munmap(mbuf, strlen(buf));
    show_timestamps(fd);

    close(fd);
}
