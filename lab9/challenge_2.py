#!/usr/bin/env python3
import binascii
from capstone import *
import sys
from unicorn import *
from unicorn.x86_const import *
from keystone import *
import random
import traceback
import math

# TODO
# - prettier printing

SYS_exit = 60
nskip = 0

call_template = """
push    {}
push    {}
call    func
ret
func:
"""

md = Cs(CS_ARCH_X86, CS_MODE_64)
last_instruction = ""
single_step_mode = False


def dump_regs(uc):
    rax = uc.reg_read(UC_X86_REG_RAX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    rip = uc.reg_read(UC_X86_REG_RIP)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
    r10 = uc.reg_read(UC_X86_REG_R10)
    r11 = uc.reg_read(UC_X86_REG_R11)
    r12 = uc.reg_read(UC_X86_REG_R12)
    r13 = uc.reg_read(UC_X86_REG_R13)
    r14 = uc.reg_read(UC_X86_REG_R14)
    r15 = uc.reg_read(UC_X86_REG_R15)
    print('------------------')
    print("RAX: {:#x}".format(rax))
    print("RBX: {:#x}".format(rbx))
    print("RCX: {:#x}".format(rcx))
    print("RDX: {:#x}".format(rdx))
    print("RSI: {:#x}".format(rsi))
    print("RDI: {:#x}".format(rdi))
    print("RBP: {:#x}".format(rbp))
    print("RSP: {:#x}".format(rsp))
    print("RIP: {:#x}".format(rip))
    print("R8: {:#x}".format(r8))
    print("R9: {:#x}".format(r9))
    print("R10: {:#x}".format(r10))
    print("R11: {:#x}".format(r11))
    print("R12: {:#x}".format(r12))
    print("R13: {:#x}".format(r13))
    print("R14: {:#x}".format(r14))
    print("R15: {:#x}".format(r15))
    print('------------------')


def print_single_step_menu(uc):
    dump_regs(uc)


def hook_code(uc, address, size, user_data):
    global last_instruction, single_step_mode, nskip
    code = uc.mem_read(address, size)

    for i in md.disasm(code, address):
        if single_step_mode:
            if nskip == 0:
                print_single_step_menu(uc)
                print("Current Instruction: {:#x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))
                print('------------------')
                input("> Press enter to step: ")
            else:
                nskip -= 1
        else:
            print("Current Instruction: {:#x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))
            print('------------------')

        last_instruction = i.mnemonic
        if i.mnemonic == "syscall":
            print("stopping emulation!")
            uc.emu_stop()
        break


def do_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    if rax != math.gcd(args[0], args[1]):
        return False
    return True


def print_flag():
    print("UVTCA{XXXXXXXXXXXXXXXXXXXX}")


def check(uc, args):
    return do_check(uc, args)


def do_emu(code, single_step):
    global single_step_mode, nskip

    if code is None:
        print("Please enter some code!")
        return

    addr = 0x1000
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    single_step_mode = single_step

    random.seed()
    args = random.sample(range(1, 10000), 2)

    # TODO: decrease stack size
    mu.mem_map(addr, 2 * 1024 * 1024)
        
    template = call_template.format(args[0], args[1])
    code = template + code
    plain_code = code
    code = asm_to_bytes(code)

    mu.mem_write(addr, code)

    # call items needs a valid stack pointer
    mu.reg_write(UC_X86_REG_RSP, addr + (2 * 1024 * 1024))


    mu.hook_add(UC_HOOK_CODE, hook_code, addr, addr + len(code))
    
    # Display the entire program 
    code = mu.mem_read(addr, addr + 0x50)
    counter = 0
    print('------------------')
    print("Program in Memory:")
    print('------------------')
    for i in md.disasm(code, addr):
        print("{:#x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))
        counter += 1
        if counter > len(plain_code.split()) // 2:
            break

    try:
        mu.emu_start(addr, addr + len(code))
    except UcError as e:
        pass

    print("Emulation done!")
    dump_regs(mu)

    if check(mu, args):
        print_flag()
    else:
        print("Failed!")


def asm_to_bytes(code):
    print("code: {}".format(code))
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(code)

    if (encoding is None) or (count == 0):
        print("Couldn't compile your code :(")
        sys.exit()

    return bytes(encoding)


def main():
    single_step = False

    print("""
       .-""-"-""-.
      /           \\
      | .--.-.--. |
      |` >       `|
      | <         |
      (__..---..__)
     (`|\o_/ \_o/|`)
      \(    >    )/   Gr gr gr
    [>=|   ---   |=<]
       \__\   /__/
           '-'
    """)

    print("Grr me some grrembly code, end with empty grline")
    code = ""
    cnt = 0
    while True:
        cnt += 1

        if cnt == 200:
            print("Maximum numbers of instructions exceeded!")
            sys.exit()

        tmp = input("").lstrip() + "\n"
        if tmp == "\n":
            break

        code += tmp

    if input("Do you want single-step mode? (Y/N) ").upper() == "Y":
        single_step = True

    do_emu(code, single_step)


if __name__ == "__main__":
    main()
    sys.exit()
