/* SPDX-License-Identifier: Apache-2.0 */
/* Minimal x86 boot payload for the held KVM test. No filesystem or network. */
    .pushsection .rodata.kernel_cow_guest,"a",@progbits
    .globl kernel_cow_guest_start, kernel_cow_guest_end
    .hidden kernel_cow_guest_start, kernel_cow_guest_end
kernel_cow_guest_start:
    mov edi, 0x400000
    mov ecx, 0x4d21
    mov byte ptr [rdi + 0x1000], 0xa4
    mov byte ptr [rdi], 0x31
.Lwait_address:
    pause
    mov rbx, [rdi + 0x20]
    test rbx, rbx
    jz .Lwait_address
    /* Identity map the actual Guest gate MMIO address reported by the VMM. */
    mov rax, rbx
    shr rax, 30
    mov qword ptr [rax * 8 + 0xa000], 0x3ff003
    mov rdx, rbx
    and edx, 0x3fffffff
    shr edx, 21
    mov eax, ebx
    and eax, 0xffe00000
    or eax, 0x9b
    mov [rdx * 8 + 0x3ff000], rax
    mov dword ptr [rbx + 0x70], 1
    mov dword ptr [rbx + 0x70], 3
    mov dword ptr [rbx + 0x24], 1
    mov dword ptr [rbx + 0x20], 1
    mov dword ptr [rbx + 0x70], 11
    mov dword ptr [rbx + 0x70], 15
    xor r10d, r10d                 /* Last gate revision. */
    xor r11d, r11d                 /* Ordinary guest work is parked. */
.Lpoll:
    pause
    mov eax, [rbx + 0x100]
    cmp eax, r10d
    je .Lwork
    mov r10d, eax
    mov eax, [rbx + 0x108]        /* Gate opcode. */
    cmp eax, 4
    je .Larmed
    cmp eax, 5
    je .Lparked
    cmp eax, 6
    je .Lidentity
    cmp eax, 2
    je .Lrelease
    cmp eax, 7
    jne .Lwork
.Lrelease:
    xor r11d, r11d
    mov edx, 2
    jmp .Lack
.Larmed:
    mov edx, 1
    jmp .Lack
.Lparked:
    mov r11d, 1
    mov edx, 6
    jmp .Lack
.Lidentity:
    mov edx, 7
.Lack:
    mov eax, [rbx + 0x104]
    mov [rbx + 0x124], eax
    mov eax, [rbx + 0x114]
    mov [rbx + 0x128], eax
    mov eax, [rbx + 0x118]
    mov [rbx + 0x12c], eax
    mov eax, [rbx + 0x11c]
    mov [rbx + 0x130], eax
    mov eax, [rbx + 0x120]
    mov [rbx + 0x134], eax
    mov dword ptr [rbx + 0x138], 0
    mov [rbx + 0x13c], edx
.Lwork:
    test r11d, r11d
    jnz .Lpoll
    mov al, [rdi + 2]
    test al, al
    jz .Lpoll
    cmp al, 0xff
    je .Lread
    mov [rdi], al
    jmp .Ldone
.Lread:
    mov al, [rdi + 0x1000]
    mov [rdi + 3], al
    mov [rdi + 4], ecx
.Ldone:
    mov byte ptr [rdi + 2], 0
    jmp .Lpoll
kernel_cow_guest_end:
    .popsection
