.section .note.GNU-stack,"",@progbits

.intel_syntax noprefix

.extern getrandom

.section .text
.global randombytes

randombytes:
	# The function signature for libc's getrandom is:
	#   ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
	#
	# According to the x86-64 System V ABI, arguments are passed in:
	#   RDI: 1st arg (buf)
	#   RSI: 2nd arg (buflen)
	#   RDX: 3rd arg (flags)
	#
	# Our function receives the first two arguments from its caller in
	# RDI and RSI, so they are already in the right place. We just
	# need to set the flags.

	xor edx, edx # Set the 'flags' argument (rdx) to 0

	# Call the getrandom function from libc. The '@plt' suffix
	# tells the assembler to generate a call to the Procedure
	# Linkage Table entry for 'getrandom'.
	call getrandom@plt

	# The return value is in RAX.
	# - On success, it's the number of bytes written.
	# - On error, it's -1.
	# We will return 0 for success and -1 for failure.

	cmp rax, rsi   	# Did we get the number of bytes we asked for?
	jne .Lfailure  	# If not, treat as a failure.

	# Success
	xor rax, rax 	# Return 0
	ret

.Lfailure:
	mov rax, -1	# Return -1
	ret
