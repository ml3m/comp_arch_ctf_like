section .bss
    output resb 24                        ; Reserve 24 bytes for the output.

section .data
    input db "TTWGD}j<z=8~R>iO%'&'xt{a8g", 0   ; Input data
    input_len equ $-input                    ; Length of the input

section .text
    global _start                         ; Define the entry point for ld

_start:
    ; Prepare the initial key and the loop counter
    mov rsi, input     
    mov rdi, output    
    mov rcx, input_len 
    mov r8b, 0x1                          
    jmp loop

loop:
    cmp rcx, 0     
    je exit
    mov al, [rsi]  
    xor al, r8b    
    mov [rdi], al  
    inc rdi        
    inc r8b        
    inc rsi        
    dec rcx        
    jmp loop   

exit:
    ; End of program
    push rax
    ret                              

section .bss
    resb 8