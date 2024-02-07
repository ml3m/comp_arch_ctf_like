section .data
input_data: dd 0x000000004b434348 ; Define input data
input_len: dd 0x0000000000000004  ; Define the length of the input data

section .bss
lut resb 256*4            ; Reserve space for 256 dwords (one dword is 4 bytes)

section .text
global _start             ; Declare global entry point for the linker

_start:
    push   rbp
    mov    rbp, rsp
    call   hash 
    leave
    ret

generate_table:
    push   rbp
    mov    rbp, rsp
    sub    rsp, 16   ; Reserve space on the stack for local variables
    
    ; Initialize loop variable i (at RBP-8) to 0
    mov    DWORD [rbp-8], 0

outer_loop:
    cmp    DWORD [rbp-8], 256 
    jge    end_outer_loop

    ; Initialize local variables
    mov    eax, DWORD [rbp-8]
    mov    DWORD [rbp-12], eax
    mov    DWORD [rbp-16], 0

inner_loop:
    cmp    DWORD [rbp-16], 8  
    jge    end_inner_loop   

    ; Perform bitwise operations
    mov    eax, DWORD [rbp-12]
    test   al, 1
    jz     no_xor
    shr    eax, 1
    xor    eax, 0xEDB88320  ; Special Polynomial 👀
    jmp    inner_loop_continue

no_xor:
    shr    eax, 1

inner_loop_continue:
    mov    DWORD [rbp-12], eax
    add    DWORD [rbp-16], 1  ; Increment counter
    jmp    inner_loop

end_inner_loop:
    ; Store result in lut[i]
    mov    eax, DWORD [rbp-8]
    lea    rdi, [lut+eax*4] 
    mov    eax, DWORD [rbp-12]
    mov    [rdi], eax

    ; Increment other counter
    add    DWORD [rbp-8], 1
    jmp    outer_loop
    
end_outer_loop:
    add    rsp, 16    ; Clean up stack
    pop    rbp
    ret

hash:
    push   rbp
    mov    rbp, rsp
    sub    rsp, 32    ; Reserve space for local variables

    ; Call generate_table to initialize the lookup table
    call   generate_table

    ; Initialize local variables
    mov    rsi, rdi                   ; RSI points to the input data
    mov    DWORD [rbp-20], 0xffffffff
    mov    rdx, [input_len]           ; RDX is the input length
    mov    QWORD [rbp-24], 0          ; Initialize input index

crc_loop:
    cmp    QWORD [rbp-24], rdx 
    jge    crc_done           

    ; Compute the index into the lookup table
    xor    rcx, rcx
    xor    rax, rax 
    mov    ecx, DWORD [rbp-24]  
    mov    al, BYTE [input_data+ecx] 
    xor    eax, DWORD [rbp-20]
    and    eax, 0xff
    shr    DWORD [rbp-20], 8 
    imul   eax, 4
    and    eax, 0xff
    mov    ebx, DWORD [lut+eax]
    xor    DWORD [rbp-20], ebx

    ; Increment the input index i and repeat the loop
    add    QWORD [rbp-24], 1
    jmp    crc_loop

crc_done:
    mov    r12, 0xffffffff
    xor    [rbp-20], r12       ; Finalize the hash value
    xor    rax, rax
    mov    eax, DWORD [rbp-20] ; Move the final hash value into the return register (RAX)
    add    rsp, 32             ; Clean up stack
    pop    rbp
    ret