bits 64

; Each function shares one instruction window with another function.  The
; outliner replaces the window with a call, which pushes a return address at
; [rsp-8, rsp).  The red-zone prefix writes a slot that the window may or may
; not read afterwards; the outliner must only accept the sites where the slot
; is dead.

; Allowed: the slot written before the window is never read.
leaf_ok_a:
    mov [rsp-8], rax
    mov eax, [rdi]
    add eax, [rsi]
    imul eax, eax
    add eax, [rdx]
    mov [rcx], eax
    xor eax, eax
    ret
leaf_ok_a_end:

leaf_ok_b:
    mov [rsp-8], rcx
    mov eax, [rdi]
    add eax, [rsi]
    imul eax, eax
    add eax, [rdx]
    mov [rcx], eax
    xor eax, eax
    ret
leaf_ok_b_end:

; Rejected: the slot is read after the window.
leaf_read_a:
    mov [rsp-8], rax
    mov ecx, [rdi]
    sub ecx, [rsi]
    imul ecx, ecx
    sub ecx, [rdx]
    mov [rcx], ecx
    xor ecx, ecx
    mov rbx, [rsp-8]
    ret
leaf_read_a_end:

leaf_read_b:
    mov [rsp-8], rcx
    mov ecx, [rdi]
    sub ecx, [rsi]
    imul ecx, ecx
    sub ecx, [rdx]
    mov [rcx], ecx
    xor ecx, ecx
    mov rdx, [rsp-8]
    ret
leaf_read_b_end:

; Allowed: the write is deeper than the 8-byte return-address slot.
leaf_deep_a:
    mov [rsp-16], rax
    mov edx, [rdi]
    xor edx, [rsi]
    imul edx, edx
    xor edx, [rdx]
    mov [rcx], edx
    xor edx, edx
    ret
leaf_deep_a_end:

leaf_deep_b:
    mov [rsp-16], rcx
    mov edx, [rdi]
    xor edx, [rsi]
    imul edx, edx
    xor edx, [rdx]
    mov [rcx], edx
    xor edx, edx
    ret
leaf_deep_b_end:

; Allowed: a full-width write replaces the slot before it is read.
leaf_over_a:
    mov [rsp-8], rax
    mov ebx, [rdi]
    and ebx, [rsi]
    imul ebx, ebx
    and ebx, [rdx]
    mov [rcx], ebx
    xor ebx, ebx
    mov [rsp-8], rbx
    mov rcx, [rsp-8]
    ret
leaf_over_a_end:

leaf_over_b:
    mov [rsp-8], rcx
    mov ebx, [rdi]
    and ebx, [rsi]
    imul ebx, ebx
    and ebx, [rdx]
    mov [rcx], ebx
    xor ebx, ebx
    mov [rsp-8], rdx
    mov rsi, [rsp-8]
    ret
leaf_over_b_end:

; Allowed: a call at the same stack depth overwrites the slot.
leaf_call_a:
    mov [rsp-8], rax
    mov esi, [rdi]
    or esi, [rsi]
    imul esi, esi
    or esi, [rdx]
    mov [rcx], esi
    xor esi, esi
    call helper
    mov rbx, [rsp-8]
    ret
leaf_call_a_end:

leaf_call_b:
    mov [rsp-8], rcx
    mov esi, [rdi]
    or esi, [rsi]
    imul esi, esi
    or esi, [rdx]
    mov [rcx], esi
    xor esi, esi
    call helper
    mov rdx, [rsp-8]
    ret
leaf_call_b_end:

; Rejected: the moved window itself reads the slot.
leaf_winread_a:
    mov ebx, [rsp-8]
    mov edi, [rdi]
    add edi, [rsi]
    imul edi, edi
    add edi, [rdx]
    mov [rcx], edi
    mov rbx, rax
    ret
leaf_winread_a_end:

leaf_winread_b:
    mov ebx, [rsp-8]
    mov edi, [rdi]
    add edi, [rsi]
    imul edi, edi
    add edi, [rdx]
    mov [rcx], edi
    mov rdx, rax
    ret
leaf_winread_b_end:

; Mixed: two safe sites and one unsafe site share one window.  The outliner
; must keep the safe sites and drop only the unsafe one.
mixed_safe_a:
    mov [rsp-8], rax
    mov r8d, [rdi]
    test r8d, [rsi]
    imul r8d, r8d
    test r8d, [rdx]
    mov [rcx], r8d
    not r8d
    ret
mixed_safe_a_end:

mixed_safe_b:
    mov [rsp-8], rcx
    mov r8d, [rdi]
    test r8d, [rsi]
    imul r8d, r8d
    test r8d, [rdx]
    mov [rcx], r8d
    not r8d
    ret
mixed_safe_b_end:

mixed_unsafe:
    mov [rsp-8], rdx
    mov r8d, [rdi]
    test r8d, [rsi]
    imul r8d, r8d
    test r8d, [rdx]
    mov [rcx], r8d
    not r8d
    mov rsi, [rsp-8]
    ret
mixed_unsafe_end:

; Rejected: a register alias hides the read of the slot.
leaf_alias_a:
    mov [rsp-8], rax
    mov r9d, [rdi]
    add r9d, [rsi]
    imul r9d, r9d
    add r9d, [rdx]
    mov [rcx], r9d
    not r9d
    lea rbx, [rsp-8]
    mov rcx, [rbx]
    ret
leaf_alias_a_end:

leaf_alias_b:
    mov [rsp-8], rcx
    mov r9d, [rdi]
    add r9d, [rsi]
    imul r9d, r9d
    add r9d, [rdx]
    mov [rcx], r9d
    not r9d
    lea rdx, [rsp-8]
    mov rsi, [rdx]
    ret
leaf_alias_b_end:

; Call target for the leaf_call group.
helper:
    ret
helper_end:
