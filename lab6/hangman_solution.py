from pwn import *

def solve_challenge(host, port):
    conn=remote(host, port)

    l=[80, 82,79,67,69, 83, 83, 79, 80, 83] 
    for x in range (10):
        prompt = conn.recvuntil(":").decode()
        print(prompt)
        print(f"LOADK Reg{x} "+f"{ l[x]}")
        conn.sendline(f"LOADK Reg{x} "+ f" {l[x]}")

    conn.sendline(b"END")
    conn.sendline(b"")

    conn.interactive()
    conn.close ()


if __name__ == "__main__":
    host = "85.120.206.124"
    port = 31349
    solve_challenge(host, port)
