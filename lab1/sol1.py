#!/usr/bin/python3
from pwn import *

def main(host, port):
    conn = remote(host, port) 
    # context.log_level = 'DEBUG'
    for i in range(49):
        string1 = conn.recvuntil(":")
        print("output prompt is : ", string1)

        a = string1.strip().split()
        str_num = a[-2]
        print("number = ",str_num)

        binaryform = bin(int(str_num))
        print("binaryform:", binaryform)

        conn.sendline(binaryform.encode())

        response_to_sent = conn.recvline().decode()
        print("serverrr response", response_to_sent)

    server_response = conn.recvline()
    print("final response = ", server_response)
    conn.interactive()

if __name__ == "__main__":
    host = "85.120.206.124"
    port = 31338
    main(host, port)