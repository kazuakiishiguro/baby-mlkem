section .text
global randombytes

randombytes:
	;; rdi: buffer pointer
	;; rsi: buffer length
	mov eax, 318		; syscall number for getrandom
	xor edx, edx		; flags = 0
	syscall

	;; exit(1) if getrandom did not fill the entire buffer
	cmp rax, rsi
	jne .Lerror
	ret

.Lerror:
	mov edi, 1 		; exit status
	mov eax, 60 		; syscall number for exit
	syscall
