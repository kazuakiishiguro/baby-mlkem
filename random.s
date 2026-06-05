.section .note.GNU-stack,"",@progbits
.intel_syntax noprefix

.section .bss
.align 16
random_buffer:
    .zero 256
bytes_in_buffer:
    .quad 0

.section .text
.global randombytes

randombytes:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    mov r13, rsi

.Lloop:
    test r13, r13
    je .Lsuccess

    mov r14, [rip + bytes_in_buffer]
    test r14, r14
    jne .Lserve

.Lrefill:
    mov rax, 318
    lea rdi, [rip + random_buffer]
    mov rsi, 256
    xor rdx, rdx
    syscall
    test rax, rax
    jle .Lfailure
    mov [rip + bytes_in_buffer], rax
    mov r14, rax

.Lserve:
    lea rbx, [rip + random_buffer + 256]
    sub rbx, r14
    mov r15, r13
    cmp r15, r14
    cmova r15, r14

    mov rdi, r12
    mov rsi, rbx
    mov rcx, r15
    rep movsb

    add r12, r15
    sub r13, r15
    sub qword ptr [rip + bytes_in_buffer], r15
    jmp .Lloop

.Lsuccess:
    xor rax, rax
    jmp .Lexit

.Lfailure:
    mov rax, -1

.Lexit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
