#!/usr/local/bin/python3
import os
from pwn import *

SECRET_VALUE = ''
SECRET_ADDR = ''

class CustomRAM:
    def __init__(self):
        self.memory = [[0]*32 for _ in range(120)]

    def read(self, row, col):
        return self.memory[row][col]

    def write(self, row, col, value):
        self.memory[row][col] = value

def init_memory(ram):
    global SECRET_VALUE 
    global SECRET_ADDR

    random_value1 = os.urandom(32)
    random_value2 = os.urandom(32)
    SECRET_VALUE = xor(random_value1, random_value2)

    random_addr1 = ord(os.urandom(1)) % 120
    random_addr2 = ord(os.urandom(1)) % 120
    secret_addr = ord(os.urandom(1)) % 10

    while random_addr2 == random_addr1:
        random_addr2 = ord(os.urandom(1)) % 120

    while secret_addr == random_addr1 or secret_addr == random_addr2:
        secret_addr = ord(os.urandom(1)) % 10
    
    SECRET_ADDR = secret_addr

    for i in range(32):
        data = b'\x01\x00'
        data += p16(random_addr1)
        data += p16(0+i)
        data += p64(random_value1[i] & 0xff)
        control_wire_write(ram, data)

    for i in range(32):
        data = b'\x01\x00'
        data += p16(random_addr2)
        data += p16(0+i)
        data += p64(random_value2[i] & 0xff)
        control_wire_write(ram, data)


def control_wire_read(ram, data):
    serialized_input = data
    
    if u16(serialized_input[0:2]) == 0x0000:
        row = u16(serialized_input[2:4])
        col = u16(serialized_input[4:6])
        print(f"0x{ram.read(row, col):02x}")
        return ram.read(row, col)
    else:
        print("[!] Invalid Data\n")
        return None

def control_wire_write(ram, data):
    serialized_input = data

    if u16(serialized_input[0:2]) == 0x0001:
        row = u16(serialized_input[2:4])
        col = u16(serialized_input[4:6])
        value = u64(serialized_input[6:14])
        ram.write(row, col, value)
        return 1
    else:
        print("[!] Invalid Data\n")
        return 0

def control_wire_clear(ram, data):
    serialized_input = data

    if u16(serialized_input[0:2]) == 0x0002:
        row = u16(serialized_input[2:4])
        col = u16(serialized_input[4:6])
        value = 0
        ram.write(row, col, value)
        return 1
    else:
        print("[!] Invalid Data\n")
        return 0

def control_wire_check(ram, data):
    global SECRET_ADDR
    global SECRET_VALUE

    serialized_input = data

    if u16(serialized_input[0:2]) == 0xcafe:
        for i in range(32):
            if ram.read(SECRET_ADDR, i) == SECRET_VALUE[i]:
                flag = os.getenv("FLAG")
                print("Congrats! Here is your flag:", flag)
                return 1
            else:
                return 0
    else:
        print("[!] Invalid Data\n")
        return 0

def print_memory(ram):
    print('-'*(32*3))
    for row_num in range(len(ram.memory)):
        rn = str(row_num).rjust(3, ' ')
        print(f'[{rn}]',ram.memory[row_num])
    print('-'*(32*3))

def banner():
    print("""       
>  <  T  R  A  F  F  I  C  >  <               
+--+--+--+--+--+--+--+--+--+--+
|41|41|41|41|00|00|00|00|00|00|
+--+--+--+--+--+--+--+--+--+--+
|00|00|00|00|00|CA|00|00|00|00|
+--+--+--+--+--+--+--+--+--+--+
|00|00|00|00|00|00|FE|00|00|00|
+--+--+--+--+--+--+--+--+--+--+
...
+--+--+--+--+--+--+--+--+--+--+
|00|00|00|00|00|00|00|BA|00|00|
+--+--+--+--+--+--+--+--+--+--+
|00|00|00|00|00|00|00|00|BE|00|
+--+--+--+--+--+--+--+--+--+--+
|00|00|00|00|00|00|00|00|00|00|
+--+--+--+--+--+--+--+--+--+--+
<  >  C  O  N  T  R  O  L  <  >
          
          """)

def menu():
    print('[1] Help')
    print('[2] Read Data From Memory')
    print('[3] Write Data To Memory')
    print('[4] Clear Memory')
    print('[5] Print Memory - BETA')
    print('[6] Exit')

def helper():
    print("""
---------------------------------------
\033[1mHELP\033[0m
    - prints this text\n
\033[1mREAD DATA FROM MEMORY\033[0m
    - reads a custom serialized data which encodes the action number, the row, the column and the amount of bytes to be read\n
\033[1mWRITE DATA TO MEMORY\033[0m
    - reads a custom serialized data which encodes the action number, the row, the column and the byte to be written\n
\033[1mCLEAR MEMORY\033[0m
    - reads a custom serialized data which encodes the action number, the row, the column and the amount of bytes to be cleared\n
\033[1mPRINT MEMORY\033[0m
    - prints the entire memory region - this operation is only available in dev mode (locally), not in prod mode (on the remote server)\n
\033[1mEXIT\033[0m
    - exits the program
---------------------------------------
          """)

def read_user_input():
    return input(" > ").strip()

def main():
    banner()
    ram = CustomRAM()
    init_memory(ram)

    while 1:
        menu()
        user_input = read_user_input().encode()

        if user_input == b"1":
            helper()

        elif user_input == b"2":
            data = input(" > Enter serialized data: ").strip()
            data = binascii.unhexlify(data.encode())
            control_wire_read(ram, data)

        elif user_input == b"3":
            data = input(" > Enter serialized data: ").strip()
            data = binascii.unhexlify(data.encode())
            control_wire_write(ram, data)

        elif user_input == b"4":
            data = input(" > Enter serialized data: ").strip()
            data = binascii.unhexlify(data.encode())
            control_wire_clear(ram, data)

        elif user_input == b"5":
            if os.getenv("IS_PROD"):
                print("[!] Not available in production!\n")
            else:
                print_memory(ram)

        elif user_input == b"6":
            print("[*] Good Bye!")
            exit(0)

        elif user_input == b"1337":
            data = input(" > Enter serialized data: ").strip()
            data = binascii.unhexlify(data.encode())
            control_wire_check(ram, data)

        else:
            print("[!] Invalid menu entry")

if __name__ == "__main__":
    main()
