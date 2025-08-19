# -----------------------------------------------------------------------------
# random.s: A high-performance random number generation wrapper
#
# Features:
#   - Employs a glibc-like internal buffering strategy to reduce syscalls.
#   - Uses SSE instructions for 16-byte requests to accelerate memory copies.
# -----------------------------------------------------------------------------

.section .note.GNU-stack,"",@progbits
.intel_syntax noprefix

# --- Global Variables (Buffer and Counter) ---
# The .bss section is zero-initialized at program start.
.section .bss
.align 16
# Buffer to store random data fetched from the OS (256 bytes).
random_buffer:
    .zero 256
# Number of valid bytes remaining in the buffer.
bytes_in_buffer:
    .quad 0

.section .text
.global randombytes

# =============================================================================
# Function: randombytes(rdi: *out, rsi: outlen)
# Returns: rax = 0 (success) or -1 (failure)
# =============================================================================
randombytes:
    # --- 0. Save callee-saved registers (ABI compliance) ---
    push rbx
    push r12

    # --- 1. Check if the buffer has enough data ---
    mov r12, [rip + bytes_in_buffer] # Load remaining byte count into r12
    cmp r12, rsi                     # Is remaining_bytes >= requested_bytes?
    jge .Lserve_from_buffer          # If yes, jump to the copy routine

# --- 2. Buffer is empty or insufficient; refill via syscall ---
.Lrefill_buffer:
    mov rax, 318                     # getrandom syscall number

    # Temporarily save rdi and rsi as the syscall will clobber them
    push rdi
    push rsi

    lea rdi, [rip + random_buffer]   # syscall arg rdi: our internal buffer
    mov rsi, 256                     # syscall arg rsi: request 256 bytes
    xor rdx, rdx                     # syscall arg rdx: flags = 0
    syscall                          # Invoke the kernel!

    pop rsi
    pop rdi

    test rax, rax
    js .Lfailure                     # If the syscall failed (< 0)

    mov [rip + bytes_in_buffer], rax
    mov r12, rax

    cmp r12, rsi
    jl .Lfailure                     # If still not enough data after refill, it's an error

# --- 3. Copy data from our buffer to the user's buffer ---
.Lserve_from_buffer:
    # Calculate source address: rbx = &buffer_end - remaining_bytes
    lea rbx, [rip + random_buffer + 256]
    sub rbx, r12

    # ★★★ Optimization Branch ★★★
    # Check if the requested size is 16 bytes
    cmp rsi, 16
    je .Lcopy_16_bytes_fast_path     # If so, take the fast path

# --- 3a. Generic Copy (for sizes other than 16 bytes) ---
.Lgeneric_copy:
    mov rcx, rsi
    push rsi
    mov rsi, rbx
    rep movsb                        # Generic memory copy
    pop rsi
    jmp .Lupdate_counter

# --- 3b. 16-Byte Specialized Fast Copy ---
.Lcopy_16_bytes_fast_path:
    movups xmm0, [rbx]               # Load 16 bytes from internal buffer (rbx) into xmm0
    movups [rdi], xmm0               # Store 16 bytes from xmm0 to user buffer (rdi)

# --- 3c. Update Buffer Counter ---
.Lupdate_counter:
    sub [rip + bytes_in_buffer], rsi

# --- 4. Success and Exit ---
    xor rax, rax
    jmp .Lexit

# --- 5. Error Handling ---
.Lfailure:
    mov rax, -1

# --- 6. Epilogue ---
.Lexit:
    pop r12                          # Restore saved registers
    pop rbx
    ret                              # Return to caller
