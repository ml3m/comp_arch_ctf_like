#!/usr/local/bin/python3
import os 

r1_8bytes = 0
r2_5bytes = 0
r3_3bytes = 0

def display_registers():
    global r1_8bytes, r2_5bytes, r3_3bytes

    register8_display = '[' + ' 0 |'*(8-r1_8bytes) + ' 1 |'*r1_8bytes
    register8_display = register8_display[:len(register8_display)-1] + ']'
    register5_display = '[' + ' 0 |'*(5-r2_5bytes) + ' 1 |'*r2_5bytes
    register5_display = register5_display[:len(register5_display)-1] + ']'
    register3_display = '[' + ' 0 |'*(3-r3_3bytes) + ' 1 |'*r3_3bytes
    register3_display = register3_display[:len(register3_display)-1] + ']'
    print('\n' + '-'*48)
    print(f"Register R1: {register8_display}")
    print(f"Register R2: {register5_display}")
    print(f"Register R3: {register3_display}")
    print('-'*48)

def print_flag():
    flag = os.getenv("FLAG")
    print("Congrats! Here is your flag:", flag)

def validate(register):
    global r1_8bytes, r2_5bytes, r3_3bytes

    if register == "R1":
        if r1_8bytes == 4:
            print_flag()
    elif register == "R2":
        if r2_5bytes == 4:
            print_flag()
    elif register == "R3":
        if r3_3bytes == 4:
            print_flag()
    else:
        print("Invalid Register!")

def fill(register):
    global r1_8bytes, r2_5bytes, r3_3bytes

    if register == "R1":
        r1_8bytes = 8
    elif register == "R2":
        r2_5bytes = 5
    elif register == "R3":
        r3_3bytes = 3
    else:
        print("Invalid Register!")

def empty(register):
    global r1_8bytes, r2_5bytes, r3_3bytes

    if register == "R1":
        r1_8bytes = 0
    elif register == "R2":
        r2_5bytes = 0
    elif register == "R3":
        r3_3bytes = 0
    else:
        print("Invalid Register!")

def move(source, target, source_capacity, target_capacity):
    global r1_8bytes, r2_5bytes, r3_3bytes

    print("target=", target)
    print("source=", source)
    print("target capacity=", target_capacity)
    print("source capacity=", source_capacity)

    if source > 0:
        if target == target_capacity:
            print("Insufficient space in target register")
        else:
            space = target_capacity - target 
            print("space=", space)

            if source < space:
                space = source

            if source_capacity == 8:
                r1_8bytes = source - space 
            elif source_capacity == 5:
                r2_5bytes = source - space 
            elif source_capacity == 3:
                r3_3bytes = source - space 
            else:
                print("IDK what is going on")

            if target_capacity == 8:
                r1_8bytes = target + space 
            elif target_capacity == 5:
                r2_5bytes = target + space 
            elif target_capacity == 3:
                r3_3bytes = target + space 
            else:
                print("IDK what is going on")
    else:
        print("There is nothing to move")

def main():

    while True:
        display_registers()
        print("")
        print("1. Fill a register")
        print("2. Empty a register")
        print("3. Move from one register to another")
        print("4. Quit")

        choice = input(" > ").strip()

        if choice == "1":
            register = input(" > Enter the register to fill (R1 / R2 / R3): ").strip()
            fill(register)

        elif choice == "2":
            register = input(" > Enter the register to empty (R1, R2, R3): ").strip()
            empty(register)

        elif choice == "3":
            source = input(" > Enter the source register (R1, R2, R3): ").strip()
            target = input(" > Enter the target register (R1, R2, R3): ").strip()
            if source == target:
                print("Source and target registers cannot be the same.")
            else:

                source_capacity = 8 if source == "R1" else (5 if source == "R2" else 3)
                target_capacity = 8 if target == "R1" else (5 if target == "R2" else 3)
                source = r1_8bytes if source == "R1" else (r2_5bytes if source == "R2" else r3_3bytes)
                target = r1_8bytes if target == "R1" else (r2_5bytes if target == "R2" else r3_3bytes)
                move(source, target, source_capacity, target_capacity)

        elif choice == "4141":
            reg = input(" > Enter the register to validate (R1, R2, R3): ").strip()
            validate(reg)

        elif choice == "4":
            print("Good Bye!")
            exit(0)
        else:
            print("Invalid choice. Please choose 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
