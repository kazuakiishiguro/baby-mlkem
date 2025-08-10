.section .note.GNU-stack,"",@progbits

.intel_syntax noprefix

.equ SYS_getrandom, 318

.section .text
.global randombytes

randombytes:
	mov eax, SYS_getrandom
	xor edx, edx
	syscall

	cmp rax, rsi
	jne .Lfailure

	xor rax, rax
	ret

.Lfailure:
	mov rax, -1
	ret
