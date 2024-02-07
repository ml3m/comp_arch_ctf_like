#!/usr/local/bin/python3
from colorama import init as colorama_init
from colorama import Style
from colorama import Fore
from pwn import *
import os
import re


# ----------------------
#        GLOBALS
# ----------------------
pc = 0
code = []
stack = []
labels = {}
regs = [0]*10


# ----------------------
#       FUNCTIONS
# ----------------------
def turn_red(text):
    return f"{Fore.RED}"+text+f"{Style.RESET_ALL}"

def turn_green(text):
    return f"{Fore.GREEN}"+text+f"{Style.RESET_ALL}"

def turn_blue(text):
    return f"{Fore.BLUE}"+text+f"{Style.RESET_ALL}"

def restore_regs():
    regs[1:] = stack[-9:]
    del stack[-9:]

def save_regs():
    stack.extend(regs[1:])

def addInstruction(opcode, p1=0, p2=0, p3=0):
    code.append( (opcode, p1, p2, p3) )

def addLabel(label_name):
    labels[label_name] = len(code)

def get_reg_idx(register_name):
    register_mapping = {'Reg0':0, \
                        'Reg1':1, \
                        'Reg2':2, \
                        'Reg3':3, \
                        'Reg4':4, \
                        'Reg5':5, \
                        'Reg6':6, \
                        'Reg7':7, \
                        'Reg8':8, \
                        'Reg9':9}
    try:
        ret = register_mapping[register_name]
    except KeyError as e:
        print (turn_red('Segmentation Fault') + ' - Invalid Register - "%s"' % turn_red(str(e)))
        exit(0)

    return ret

def exec_next():
    global pc
    global labels
    global regs

    if pc >= len(code):
        print(turn_red('Segmentation Fault') + ' - Unmapped Address')
        exit(0)

    opcode, p1, p2, p3 = code[pc]

    if os.getenv('DEBUG'):
        view_context()

    if opcode == "LOADK":
        p1 = get_reg_idx(p1)
        regs[p1] = p2

    elif opcode == "ADD":
        p1 = get_reg_idx(p1)
        p2 = get_reg_idx(p2)
        regs[p1] = regs[p1] + regs[p2]
    
    elif opcode == "DEC":
        p1 = get_reg_idx(p1)
        regs[p1] = regs[p1]-1

    elif opcode == "INC":
        p1 = get_reg_idx(p1)
        regs[p1] = regs[p1]+1
    
    elif opcode == "MOV":
        p1 = get_reg_idx(p1)
        p2 = get_reg_idx(p2)
        regs[p1] = regs[p2]
    
    elif opcode == "MULT":
        p1 = get_reg_idx(p1)
        p2 = get_reg_idx(p2)
        regs[p1] = regs[p1] * regs[p2]

    elif opcode == "CMP":
        p1 = get_reg_idx(p1)
        p2 = get_reg_idx(p2)
        if regs[p1] == regs[p2]:
            stack.append(1)
        else:
            stack.append(0)

    elif opcode == "JMPNZ":
        p1 = get_reg_idx(p1)
        if regs[p1] != 0:
            try:
                pc = labels[p2]
            except:
                print(turn_red('Segmentation Fault') + ' - Invalid Jump')
                exit(0)
        return

    elif opcode == "PUSH":
        stack.append(p1)
    
    elif opcode == "POP":
        p1 = get_reg_idx(p1)
        regs[p1] = stack.pop()
    
    elif opcode == "XOR":
        p1 = get_reg_idx(p1)
        p2 = get_reg_idx(p2)
        regs[p1] = xor(regs[p1], regs[p2])

    elif opcode == "RET":
        pc = stack.pop()
        restore_regs()
        return

    elif opcode == "CALL":
        save_regs()
        stack.append(pc+1)
        pc = labels[p1]
        return
    
    elif opcode == "END":
        pc = null
        return

    else:
        print(turn_red('Segmentation Fault') + ' - Invalid Instruction')
        exit(0)

    pc += 1

def print_program():
    global code
    global pc
    print('--------------------program--------------------')
    if len(code) == 0:
        print("%d: %s" % (0, turn_red(str(""))))
    else:
        for i in range(len(code)):
            for k in labels:
                if labels[k] == i:
                    print(k+':')
            if pc == i:
                print("%s: %s" % (turn_green(str(i).rjust(3, ' ')), turn_red(str(code[i]))))
            else:
                print("%s: %s" % (str(i).rjust(3, ' '), turn_red(str(code[i]))))

def print_registers():
    global regs
    print('-------------------registers-------------------')
    print(turn_green("Reg0 ="), str(regs[0]).ljust(4, ' '), ' | ', \
          turn_green("Reg1 ="), str(regs[1]).ljust(4, ' '), ' | ', \
          turn_green("Reg2 ="), str(regs[2]).ljust(4, ' '), ' | ')
    print(turn_green("Reg3 ="), str(regs[3]).ljust(4, ' '), ' | ', \
          turn_green("Reg4 ="), str(regs[4]).ljust(4, ' '), ' | ', \
          turn_green("Reg5 ="), str(regs[5]).ljust(4, ' '), ' | ')
    print(turn_green("Reg6 ="), str(regs[6]).ljust(4, ' '), ' | ', \
          turn_green("Reg7 ="), str(regs[7]).ljust(4, ' '), ' | ', \
          turn_green("Reg8 ="), str(regs[8]).ljust(4, ' '), ' | ')
    print(turn_green("Reg9 ="), str(regs[9]).ljust(4, ' '), ' | ')

def print_stack():
    global stack
    print('---------------------stack---------------------')
    if len(stack) == 0:
        print("%s: %s" % (hex(0), turn_blue(str(0))))
    else:
        for i in range(len(stack)):
            print("%s: %s" % (hex(i), turn_blue(str(stack[i]))))

def view_context():
    print('\n> Program Context')
    print_registers()
    print_stack()
    print_program()
    print('------------------------------------------------')

def is_valid_instruction(data):
    instruction = data.split()
    for i in [['LOADK', 2], ["ADD", 2], ["DEC", 1], \
              ["INC", 1], ["MOV", 2], ["MULT", 2], \
              ["CMP", 2], ["JMPNZ", 2], ["PUSH", 1], \
              ["POP", 1], ["XOR", 2], ["RET", 0], \
              ["CALL", 1], ["END", 0]]:
        if instruction[0] == i[0]:
            if len(instruction) - 1 == i[1]:
                return 1
            else:
                return 0
        else:
            continue
    return 0

def is_label(data):
    if len(data.split()) == 1 and data[-1] == ':':
            pattern = '[a-z]+(_[a-z]+)*'
            if bool(re.match(pattern, data[:len(data)-1])):
                return 1
    return 0

# ----------------------
#         MAIN
# ----------------------
def main():
    global pc

    colorama_init()


    # Start of the Program
    addLabel("start")

    # User supplied Instructions
    while True:
        new_instruction = input('> enter instruction: ')
        if new_instruction == '\n' or new_instruction == '':
            break 

        else:   
            new_instruction = new_instruction.strip()
            
            if is_valid_instruction(new_instruction):
                    new_instruction = new_instruction.split()

                    if len(new_instruction) >= 2:
                        if new_instruction[1].isnumeric():
                            new_instruction[1] = int(new_instruction[1])
                        if len(new_instruction) >= 3:
                            if new_instruction[2].isnumeric():
                                new_instruction[2] = int(new_instruction[2])
                    
                    if len(new_instruction) == 3:
                        addInstruction(new_instruction[0], new_instruction[1], new_instruction[2])
                    
                    elif len(new_instruction) == 2:
                        addInstruction(new_instruction[0], new_instruction[1])
                    
                    elif len(new_instruction) == 1:
                        addInstruction(new_instruction[0])

            elif is_label(new_instruction):
                addLabel(new_instruction[:-1])

            else:
                print('\n'+turn_red("Invalid Instruction!"))
                exit(0)
    
    # Instructions Automatically Appended
    addLabel("push_flag")
    addInstruction("LOADK", "Reg0", 0)
    addInstruction("PUSH", ord('U'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('V'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('T'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('C'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('A'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('{'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('r'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('e'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('a'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('l'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('f'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('l'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('a'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('g'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('o'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('n'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('s'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('e'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('r'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('v'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('e'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('r'))
    addInstruction("INC", "Reg0")
    addInstruction("PUSH", ord('}'))
    addInstruction("INC", "Reg0")
    addInstruction("JMPNZ", "Reg0", "main")

    while pc != null:
        exec_next()
        if os.getenv('DEBUG'):
            input('>')

    print("End Of Program")

if __name__ == '__main__':
    main()
