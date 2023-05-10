import idc
import idautils
import ida_typeinf

import helpers

from typing import List

# TODO: maybe decompile all again after fixing all functions?

def fix_multiple_return_signatures():
    for function_address in idautils.Functions():
        if does_function_return_multiple(function_address):
            fix_multiple_return_signature(function_address)

def does_function_return_multiple(function_start: int) -> bool:
    # If the return type already has the length of a multiple return value,
    # the fixer can ignore this function.
    function_details = helpers.get_function_details(function_start)
    if function_details.rettype.get_size() == helpers.get_multiple_return_size():
        return False

    instructions: List[int] = helpers.get_instructions_from_function(function_start)
    
    if len(instructions) < 3:
        return False
    
    index: int = -1

    for instruction in instructions:
        if helpers.is_returning_instruction(instruction):
            index = instructions.index(instruction)
    
    if index == -1 or index < 2:
        return False
    
    walkback_limit: int = 15
    if index < walkback_limit:
        walkback_limit = index + 1

    is_second_return_register_stored: bool = False
    
    for i in range(1, walkback_limit):
        insn: int = instructions[index - i]

        # If a call is made and the second return register is not filled after, it does not exist,
        # as the second return register can be trashed in a function call.
        # TODO: check for embedded return value optimization here.
        if helpers.is_calling_instruction(insn):
            break

        # TODO: check for embedded return value optimization here.
        if helpers.is_jump_outside(insn, function_start, idc.find_func_end(function_start)):
            break

        position: int = find_second_return_register_position(insn)

        if position == -1:
            continue
        elif position == 0:
            if helpers.is_moving_instruction(insn):
                is_second_return_register_stored = True
            break
        elif position == 1:
            # If the second return register is used, it is probably not stored as a return value.
            break

    if is_second_return_register_stored:
        # TODO: maybe the call site should be checked regardless, to avoid instances where rdx is detected during dereference.
        print("Reason: second return register stored.")
        return True

    for ref in idautils.CodeRefsTo(function_start, True):
        if does_caller_use_second_return_register(ref):
            return True

    return False

# Returns -1 if second return register is not used.
def find_second_return_register_position(address: int) -> int:
    if helpers.is_second_return_reg_in_operand(address, 0):
        return 0
    elif helpers.is_second_return_reg_in_operand(address, 1):
        return 1
    else:
        return -1

def does_caller_use_second_return_register(caller_address: int) -> bool:
    current_instruction: int = caller_address
    function_end: int = idc.find_func_end(caller_address)

    # Jumps do not return to the actual call site.
    if helpers.is_jump(caller_address):
        return False

    for i in range(5):
        current_instruction = idc.find_code(current_instruction, idc.SEARCH_DOWN)
        if current_instruction >= function_end or helpers.is_returning_instruction(current_instruction) or helpers.is_calling_instruction(current_instruction):
            break

        position: int = find_second_return_register_position(current_instruction)

        if position == 0:
            break
        elif position == 1:
            if helpers.is_moving_instruction(current_instruction):
                print("Reason: caller uses second return register: {}.".format(hex(current_instruction)))
                return True

    return False

def fix_multiple_return_signature(address: int):
    # Let the decompiler run on the function first to establish an initial function signature.
    helpers.decompile_function(address)

    declaration: str = generate_multiple_return_signature(address)
    print(declaration + " " + hex(address))

    result = idc.parse_decl(declaration, ida_typeinf.PT_TYP)

    idc.apply_type(address, result, idc.TINFO_DEFINITE)

def generate_multiple_return_signature(address: int) -> str:
    function_details = helpers.get_function_details(address)

    return_registers_annotation: str = get_return_registers_annotation()

    arguments: str = ""
    for i in range(function_details.size()):
        if i != 0:
            arguments = arguments + ", "
        arguments = arguments + "{} {}".format(ida_typeinf.print_tinfo('', 0, 0, idc.PRTYPE_1LINE, function_details[i].type, '', ''), function_details[i].name)
        arguments = arguments + get_argument_annotation(i)

    # Function name is discarded by parse_decl.
    return "__int128 __usercall new_func{}({});".format(return_registers_annotation, arguments)

def get_return_registers_annotation() -> str:
    platform = helpers.get_platform()

    if platform.is_pe_x64() or platform.is_elf_x64():
        return "@<rdx:rax>"
    elif platform.is_arm64():
        return "@<X1:X0>"
    else:
        return ""

def get_argument_annotation(position: int) -> str:
    annotation: str = "@<{}>"

    platform = helpers.get_platform()

    if platform.is_pe_x64():
        if position == 0:
            return annotation.format("rcx")
        if position == 1:
            return annotation.format("rdx")
        if position == 2:
            return annotation.format("r8")
        if position == 3:
            return annotation.format("r9")
        return ""
    elif platform.is_elf_x64():
        if position == 0:
            return annotation.format("rdi")
        if position == 1:
            return annotation.format("rsi")
        if position == 2:
            return annotation.format("rdx")
        if position == 3:
            return annotation.format("rcx")
        if position == 4:
            return annotation.format("r8")
        if position == 5:
            return annotation.format("r9")
        return ""
    # ARM has the same ABI across different operating systems.
    elif platform.is_arm64():
        if position == 0:
            return annotation.format("X0")
        if position == 1:
            return annotation.format("X1")
        if position == 2:
            return annotation.format("X2")
        if position == 3:
            return annotation.format("X3")
        if position == 4:
            return annotation.format("X4")
        if position == 5:
            return annotation.format("X5")
        if position == 6:
            return annotation.format("X6")
        if position == 7:
            return annotation.format("X7")
    else:
        return ""

if __name__ == "__main__":
    fix_multiple_return_signatures()

