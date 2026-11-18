.section .recr_space,"awx",@progbits
.skip 16

.macro spare name
.globl \name
.type \name,@function
\name:
.fill 143,1,0x90
ret
.size \name,.-\name
.skip 8
.endm

spare recr_spare_a
spare recr_spare_b
spare recr_spare_c
spare recr_spare_d
spare recr_spare_e
spare recr_spare_f

.globl recr_scale
.type recr_scale,@function
recr_scale:
    movabs $0x3fe0000000000000,%rax
    movq %rax,%xmm1
    addsd %xmm1,%xmm0
    ret
.size recr_scale,.-recr_scale

.section .note.GNU-stack,"",@progbits
