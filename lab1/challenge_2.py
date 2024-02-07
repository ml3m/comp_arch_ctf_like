#!/usr/local/bin/python3
import os
import random

OPERATIONS = {
    "and": lambda x, y: x & y,
    "or": lambda x, y: x | y,
    "not": lambda x: ~x & 0xFF
}

def create_circuit(i):
    equation = ["or", "and", "not"]
    if i < 25:
        return [random.choice(equation)]
    else:
        return [random.choice(equation), random.choice(equation)]

def match_operation(operation):
    if operation == "and":
        return 2
    elif operation == "or":
        return 2
    elif operation == "not":
        return 1
    else:
        return 0

def generate_sequence():
    return random.randint(1, 0xFF)


def execute_operation(operation, input1, input2 = None):
    if input2 == None:
        return OPERATIONS[operation](input1)
    else:
        return OPERATIONS[operation](input1, input2)


def banner():
    print("""
+6V -o_|_o----+----------+----------->>--------+----------+----->>
            |          |                     |          |
            LAMP1        |                     |        LAMP2
            |          | SW1                 | SW2      |
            +--A>     |o              <A--   o|         |
            |       ==|    --B>          |    |==   <B--+
            -----       |o   |             |   o|       -----
    SCR1  \   /        |   |             |   |        \   /  SCR2
            \ /        R3   ^             ^   R4        \ /
            -----        |  CR1           CR2  |        -----
            |  \       |   |             |   |       /  |
            |   +--R2--+---+             +---+--R5--+   |
            |   |                                   |   |
            |   R1                                 R6   |
            |   |                                   |   |
GND ----------+---+----------------->>----------------+---+--->>
    """)

def header():
    print("[*] Welcome to RANCIRCSIM (Random Circuit Simulator)")
    print("[*] Your task is to determin the operations which makes the citcuit return the given values.\n")

def main():

    banner()
    header()
    
    for i in range(50):
        print(f"Circuit[{i}] : ", end="")
        circuit = list(create_circuit(i))
        output = None
        for j in range(len(circuit)):
            operation = circuit[j]
            inputs = match_operation(operation)
            if inputs == 1:
                if j == 0:
                    seq1 = generate_sequence()
                else:
                    seq1 = output # the output of the previuos operation

                print(f"{bin(seq1)[2:].rjust(8, '0')} -> [OPERATION] -> ", end="")
                output = execute_operation(operation, seq1)

            elif inputs == 2:
                if j == 0:
                    seq1 = generate_sequence()
                else:
                    seq1 = output # the output of the previous operation
                
                seq2 = generate_sequence()
                print(f"{bin(seq1)[2:].rjust(8, '0'), bin(seq2)[2:].rjust(8, '0')} -> [OPERATION] -> ", end="")
                output = execute_operation(operation, seq1, seq2)

            else:
                print('[!] Invalid operation!')
                exit(1)

        print(f"{bin(output)[2:].rjust(8, '0')}")

        for i in range(len(circuit)):
            operation = circuit[i]
            operation_guess = input(f"> Guess operation {i + 1}: ")
            if operation_guess != operation:
                print("[!] Incorrect")
                exit(1)
            
    flag = os.getenv("FLAG")
    print(f"[*] Correct! The flag is: {flag}")


if __name__ == "__main__":
    main()