pop r12 ;trash don't need it
pop r11 ; the 1st value pushed.

;here we'll check if nz value then add to our 1st val.
cmp rax, 0
jz  check_rbx
add r11, rax
check_rbx:
cmp rbx, 0
jz  check_rcx
add r11, rbx
check_rcx:
cmp rcx, 0
jz  check_rdx
add r11, rcx
check_rdx:
cmp rdx, 0
jz  check_rdi
add r11, rdx
check_rdi:
cmp rdi, 0
jz  check_rsi
add r11, rdi
check_rsi:
cmp rsi, 0
jz  end
add r11, rsi
end:
mov r10, r11 ; move sum to r10


;item8

mov r10, 1
mov r11, 1
mov r12, 1
mov r13, 1
mov r14, 1
mov r15, 1
cmp rax, 0
jz  check_rbx
mov r10, rax
check_rbx:
cmp rbx, 0
jz  check_rcx
mov r11, rbx
check_rcx:
cmp rcx, 0
jz  check_rdx
mov r12, rcx
check_rdx:
cmp rdx, 0
jz  check_rdi
mov r13, rdx
check_rdi:
cmp rdi, 0
jz  check_rsi
mov r14, rdi
check_rsi:
cmp rsi, 0
jz  mult
mov r15, rsi
mult:
imul r10, r11
imul r10, r12
imul r10, r13
imul r10, r14
imul r10, r15
mov r11, r10

