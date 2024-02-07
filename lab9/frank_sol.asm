pop r11
pop rdi
pop rsi
call calculate_gcd
mov rax, 60        ; syscall number for exit
xor rdi, rdi       ; exit status
syscall

calculate_gcd:
cmp rsi, 0         ; compare rsi (second argument) with 0
je .done            ; if equal, jump to .done
cmp rdi, rsi       ; compare rdi (first argument) with rsi
jl .swap            ; if less, jump to .swap
sub rdi, rsi       ; subtract rsi from rdi
jmp calculate_gcd  ; jump to calculate_gcd

.swap:
xchg rdi, rsi       ; swap rdi and rsi
jmp calculate_gcd   ; jump to calculate_gcd

.done:
mov rax, rdi        ; move the result (GCD) to rax



;UVTCA{B3ware_f0r_1_4m_f3arl3ss_4nd_7he3ef0re_p0werfu1} 