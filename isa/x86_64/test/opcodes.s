bits 64

; Arithmetic and logic
add eax, 0x20
add rax, rbx
sub ecx, edx
imul eax, ebx
inc eax
dec rcx
neg rdx
not rsi
xor eax, eax
and eax, ebx
or eax, ebx
shl eax, 1
shr ebx, cl
sar rdx, 2
rol eax, 3
ror rbx, 4
mul ecx
div ecx
idiv ecx
cmp eax, ebx
test eax, eax

; Data movement and addressing
mov eax, ebx
mov rax, 0x1122334455667788
movzx eax, bh
movsx rax, byte [rdi]
movsxd rax, ecx
lea rax, [rdi+8]

; Stack and control flow
push rbp
pop rbp
leave
mov rsp, rbp
add rsp, 8
ret
call 0x401000
jmp 0x401000
je 0x401000
nop

; Miscellaneous
bswap eax
popcnt eax, ebx
lzcnt eax, ebx
clc
stc
cld
std
cmc
lahf
sahf
cdq
cqo
cwde
cdqe
xchg eax, ebx
bt eax, ebx

; Known-gap regression cases
mov [rbx], eax
mov r9, rdx
bsf eax, ebx
bsr eax, ebx
int3
