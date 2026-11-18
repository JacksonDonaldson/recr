.section .recr_space,"awx",@progbits
.skip 16
.option rvc

.macro spare name, size=144
.globl \name
.type \name,@function
\name:
.fill (\size-2)/2,2,0x0001
c.jr ra
.size \name,.-\name
.skip 8
.endm

spare recr_spare_a, 160
spare recr_spare_b
spare recr_spare_c
spare recr_spare_d
spare recr_spare_e
spare recr_spare_f

.section .note.GNU-stack,"",@progbits
