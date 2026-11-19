    .text
    .global _start, transform, transform_thunk, dispatched
    .type _start, @function
    .type transform, @function
    .type transform_thunk, @function
    .type dispatched, @function
_start:
#ifdef __riscv
    li a0, 7
    jal ra, transform_thunk
    lla t0, dispatch
    ld t0, 0(t0)
    jalr ra, 0(t0)
    li a7, 93
    ecall
#else
    mov $7, %edi
    call transform_thunk
    mov %eax, %edi
    call *dispatch(%rip)
    mov %eax, %edi
    mov $60, %eax
    syscall
#endif
    .size _start, .-_start
transform:
#ifdef __riscv
    addi a0, a0, 1
    addi a0, a0, 2
    nop
    ret
#else
    mov %edi, %eax
    add $3, %eax
    nop
    nop
    ret
#endif
    .size transform, .-transform
transform_thunk:
#ifdef __riscv
    j transform
#else
    jmp transform
#endif
    .size transform_thunk, .-transform_thunk
dispatched:
#ifdef __riscv
    addi a0, a0, 4
#else
    lea 4(%rdi), %eax
#endif
    ret
    .size dispatched, .-dispatched

    .section .spare, "awx", @progbits
    .global spare
    .type spare, @function
spare:
#ifdef __riscv
    .fill 63, 4, 0x00000013
#else
    .fill 255, 1, 0x90
#endif
    ret
    .size spare, .-spare

    .data
    .global counter
    .type counter, @object
counter:
    .long 3
    .size counter, .-counter
dispatch:
    .quad dispatched

    .section .note.GNU-stack, "", @progbits
