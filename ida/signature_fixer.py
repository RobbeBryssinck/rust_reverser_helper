# TODO: argument count
# TODO: keep types, names, etc.

import idc
import idautils
import ida_typeinf
import idaapi
import ida_nalt

import helpers

from typing import List

def fix_multiple_return_signatures():
    for function_address in idautils.Functions():
        if does_function_return_multiple(function_address):
            fix_multiple_return_signature(function_address)

def does_function_return_multiple(address: int) -> bool:
    instructions: List[int] = helpers.get_instructions_from_function(address)
    
    if len(instructions) < 4:
        return False
    
    mov1, mov2, add, retn = instructions[-4:]
    if idc.print_insn_mnem(mov1) != "mov" or idc.print_insn_mnem(mov2) != "mov" or idc.print_insn_mnem(add) != "add" or idc.print_insn_mnem(retn) != "retn":
        return False
    
    if idc.print_operand(mov1, 0) != "rax" or idc.print_operand(mov2, 0) != "rdx" or idc.print_operand(add, 0) != "rsp":
        return False
    
    return True

def fix_multiple_return_signature(address: int):
    declaration: str = generate_multiple_return_signature(address)
    print(declaration + " " + hex(address))

    result = idc.parse_decl(declaration, ida_typeinf.PT_TYP)

    idc.apply_type(address, result, idc.TINFO_DEFINITE)

# TODO: architecture independence
def generate_multiple_return_signature(address: int) -> str:
    arguments: str = ""
    
    function_tinfo = idaapi.tinfo_t()
    ida_nalt.get_tinfo(function_tinfo, address)
    function_details = idaapi.func_type_data_t()
    function_tinfo.get_func_details(function_details)
    
    for i in range(function_details.size()):
        if i != 0:
            arguments = arguments + ", "
        arguments = arguments + "{} {}".format(ida_typeinf.print_tinfo('', 0, 0, idc.PRTYPE_1LINE, function_details[i].type, '', ''), function_details[i].name)
        arguments = arguments + get_argument_annotation(i)

    # Function name is discarded by parse_decl.
    return "__int128 __usercall new_func@<rdx:rax>({});".format(arguments)

def get_argument_annotation(position: int) -> str:
    annotation: str = "@<{}>"

    # TODO: place architecture check here
    if True:
        if position == 0:
            return annotation.format("rcx")
        if position == 1:
            return annotation.format("rdx")
        if position == 2:
            return annotation.format("r8")
        if position == 3:
            return annotation.format("r9")
        return ""
    elif False:
        return ""
    else:
        return ""

if __name__ == "__main__":
    fix_multiple_return_signatures()