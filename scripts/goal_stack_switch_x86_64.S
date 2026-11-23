.text
.p2align 4
.globl goal_stack_call4
.type goal_stack_call4,@function
goal_stack_call4:
  pushq %rbp
  movq %rsp, %rbp
  pushq %rbx
  pushq %r12
  movq %rsp, %rbx

  movq %rdi, %r10
  movq %rsi, %rax
  movq %r9, %rsp
  andq $-16, %rsp
  movq %rdx, %rsi
  movq %rcx, %rdx
  movq %r8, %rcx
  movq %rax, %rdi
  call *%r10

  movl %eax, %r12d
  movq %rbx, %rsp
  movl %r12d, %eax
  popq %r12
  popq %rbx
  popq %rbp
  ret
.size goal_stack_call4, .-goal_stack_call4

.section .note.GNU-stack,"",@progbits
