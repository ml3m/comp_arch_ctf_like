#!/usr/bin/python3
from pwn import *

def solve_challenge(host, port):
    conn = remote(host, port)
    conn.recvuntil("values.")

    for i in range(50):
        received_data = conn.recvuntil("Guess").decode()
        print(f"Received data is {received_data}")
        segments = received_data.split("OPERATION")

        for i in range(len(segments) - 1):
            # in operation var we concatenate the strings splited by "OPERATION";
            operation = segments[i] + segments[i + 1]

            print(f"The operation is {operation}")
            conn.recvuntil("operation " + str(i + 1) + ":")
            items_in_operation = operation.split()

            if items_in_operation[3] == "->":
                conn.sendline("not")
                print("not")

            else:
                bin1 = int(items_in_operation[2][2:10], 2)
                bin2 = int(items_in_operation[3][1:9], 2)
                bin3 = items_in_operation[7]

                if bin3[0] == "(":  # if there si a parantesis that means there are 2 operations and we need to slice again
                    bin3 = bin3[2:10]

                bin3 = int(bin3, 2)

                if bin1 | bin2 == bin3:
                    conn.sendline("or")
                    print("or")

                else:
                    conn.sendline("and")
                    print("and")

    conn.interactive()
    conn.close()

if __name__ == "__main__":
    solve_challenge("85.120.206.124", 31339)