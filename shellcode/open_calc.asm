; (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
bits 64
global _main

_main:
    mov rbx, '/open';
    push rbx;
    mov rbx, '/usr/bin';
    push rbx;
    mov rdi, rsp;

    xor rbx, rbx; 
    push rbx;
    mov rbx, 'app'
    push rbx;
    mov rbx, 'culator.'
    push rbx
    mov rbx, 'ions/Cal'
    push rbx
    mov rbx, 'Applicat'
    push rbx
    mov rbx, '/System/'
    push rbx
    mov rdx, rsp;

    xor rbx, rbx;
    push rbx; argv[2] = 0
    push rdx; argv[1] = "/System/Applications/Calculator.app"
    push rdi; argv[0] = "/usr/bin/open"
    mov rsi, rsp;
    xor rdx, rdx;

    push 59
    pop rax;
    bts rax, 25;
    syscall;
