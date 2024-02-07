#!/usr/bin/env python3
import binascii
from capstone import *
import sys
from unicorn import *
from unicorn.x86_const import *
from keystone import *
import random
import traceback

# TODO
# - prettier printing

SYS_exit = 60
nskip = 0

call_0_template = """
push    {}
mov     {}, {}
call    func
ret
func:
"""

call_1_template = """
push    {}
mov     rdi, {}
call    func
ret
func:
"""

call_2_template = """
push    {}
mov     rdi, {}
mov     rsi, {}
call    func
ret
func:
"""

call_3_template = """
mov     {}, {}
mov     {}, {}
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


def item1_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    if rax != 0:
        return False
    return True


def item2_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    rsi = uc.reg_read(UC_X86_REG_RSI)

    return all((
            rax == 42, 
            rbx == 13, 
            rcx == 37, 
            rdi == 0, 
            rsi == 1337
    ))


def item3_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    return rax == (args[0] // 4)


def item4_check(uc, args):
    r10 = uc.reg_read(UC_X86_REG_R10)
    print('>>',args[0], args[2], r10)
    return r10 == (args[0] + args[2])


def item5_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    return rcx == rax == ((args[0] * 4) + 3)


def item6_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    return rax == (args[0] * args[1])


def item7_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    return (rax == SYS_exit) and (rdi == 42) and (last_instruction == "syscall")


def item8_check(uc, args):
    r11 = uc.reg_read(UC_X86_REG_R11)
    print('>>', args[0], args[1], args[2], args[3], r11)
    return r11 == (args[1] * args[3])


checks = {
    1: item1_check,
    2: item2_check,
    3: item3_check,
    4: item4_check,
    5: item5_check,
    6: item6_check,
    7: item7_check,
    8: item8_check
}


def print_flag(item):
    if item == 1:
        print("UVTCA{AAAAAAAAAAAAA")
    elif item == 2:
        print("BBBBBBBBBBBBB,")
    elif item == 3:
        print("CCCCCCCCCCCCC,")
    elif item == 4:
        print("DDDDDDDDDDDDD,")
    elif item == 5:
        print("EEEEEEEEEEEEE,")
    elif item == 6:
        print("FFFFFFFFFFFFF,")
    elif item == 7:
        print("GGGGGGGGGGGGG,")
    elif item == 8:
        print("HHHHHHHHHHHHH}")


def item_needs_call(item):
    return item in [4, 5, 6, 8]


def check(uc, item, args):
    return checks[item](uc, args)


def do_emu(item, code, single_step):
    global single_step_mode, nskip

    if code is None:
        print("Please enter some code!")
        return

    addr = 0x1000
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    single_step_mode = single_step

    random.seed()
    args = random.sample(range(1, 10000), 4)


    # TODO: decrease stack size
    mu.mem_map(addr, 2 * 1024 * 1024)
    if item_needs_call(item):
        if item == 4:
            registers = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi',]
            args[1] = registers[ args[1] % len(registers) ]
            template = call_0_template.format(args[0], args[1], args[2])
        elif item == 5:
            template = call_1_template.format(0xbadcafe, args[0])
        elif item == 6:
            template = call_2_template.format(0xbadcafe, args[0], args[1])
        elif item == 8:
            registers = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi',]
            args[0] = registers[ args[0] % len(registers) ]
            args[2] = registers[ args[2] % len(registers) ]
            if args[0] == args[2]: # ensure registers are different
                if args[2] % len(registers) < 5:
                    args[2] = args[2]+1
                else:
                    args[2] = args[2]-1

            template = call_3_template.format(args[0], args[1], args[2], args[3])

        code = template + code
        plain_code = code
        code = asm_to_bytes(code)

        mu.mem_write(addr, code)

        # call items needs a valid stack pointer
        mu.reg_write(UC_X86_REG_RSP, addr + (2 * 1024 * 1024))
    else:
        plain_code = code
        code = asm_to_bytes(code)
        mu.mem_write(addr, code)

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


    if item == 3:
        mu.reg_write(UC_X86_REG_RAX, args[0])
    else:
        if item != 4 and item != 8:
            mu.reg_write(UC_X86_REG_RAX, 0xdeadbeefcafe)

    try:
        mu.emu_start(addr, addr + len(code))
    except UcError as e:
        pass

    print("Emulation done!")
    dump_regs(mu)

    if check(mu, item, args):
        print("item {} successful!".format(item))
        print_flag(item)
    else:
        print("item {} failed!".format(item))


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
      .-""-.
     /,..___\\
    () {_____}
      (/-@-@-\)
      {`-=^=-'}
      {  `-'  } Ho Ho Ho!
       {     }
        `---'
    """)

    try:
        item = int(input("Christmas List Item (1-8) : "))
    except:
        print("Item Invalid!")
        sys.exit()

    if item not in checks:
        print("Invalid item: {}".format(item))
        return False

    print("Please give me some assembly code, end with empty line")
    code = ""
    cnt = 0
    while True:
        cnt += 1

        if cnt == 100:
            print("Maximum numbers of instructions exceeded!")
            sys.exit()

        tmp = input("").lstrip() + "\n"
        if tmp == "\n":
            break

        code += tmp

    if input("Do you want single-step mode? (Y/N) ").upper() == "Y":
        single_step = True

    do_emu(item, code, single_step)


if __name__ == "__main__":
    main()
    sys.exit()
