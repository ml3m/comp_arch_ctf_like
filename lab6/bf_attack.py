from pwn import *
import os

def solve_challenge(host, port, instructions, order):
    conn = remote(host, port)

    # Send instructions to the remote server
    for instruction in instructions:
        conn.sendline(instruction)
        response = conn.recv().decode()
        print(response)

    response = conn.recv(timeout= 0.2).decode()
    print(response)

    if response.strip() == "End Of Program":
        return True
    conn.close()

if __name__ == "__main__":
    host = "85.120.206.124" 
    port = 31348  # port
    k = 0
    flag = []
    state = True
    instructions = ['INC Reg0',
                    'JMPNZ Reg0 push_flag', 
                    'END',
                    'main:',
                    'POP Reg0',
                    'JMPNZ Reg0 char',
                    'END',
                    'stop:', 
                    'END',
                    'char:', 
                    f'LOADK Reg1 {62}', 
                    'CMP Reg0 Reg1', 
                    'POP Reg2', 
                    'JMPNZ Reg2 stop', 
                    'END',
                    '\n'
                    ]
    while state:
        start = 126
        for i in range(start, 32, -1):
            print(i)
            print(instructions)
            if solve_challenge(host, port, instructions, i):
                instructions.insert(4 + 1, 'POP Reg0')
                k+=1
                print(chr(i), 'got a character babe')
                flag.append(chr(i))
                if len(flag) == 23:
                    state = False
                break
            del instructions[10 + k]
            instructions.insert(10 + k, f"LOADK Reg1 {i-1}")
            
    # while state = false
        print(flag)
    flagg = ""
    for item in flag:
        flagg += item
    print(flagg)

# UVTCA{t1m1ng_4tt4ck_<3}
# UVTCA{t1m1ng_4~t4ck_<3}
# 85 86 84 67 65 123 116 49 109 49 110 103 95 52 116 116 52 99 107 95 60 51 125