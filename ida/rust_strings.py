import idautils
import idaapi
import idc

from typing import List

import helpers

# TODO: architecture independence (start with 32 vs 64 bit)
def identify_rust_strings():
    for function_address in idautils.Functions():
        identify_rust_strings_in_function(function_address)

def identify_rust_strings_in_function(function_address: str):
    instructions: List[int] = helpers.get_instructions_from_function(function_address)

    viable_list_length: int = len(instructions) - 2
    for i in range(viable_list_length):
        if idc.print_insn_mnem(instructions[i]) != "lea":
            continue

        source_address: int = idc.get_operand_value(instructions[i])
        if not is_in_data_section(source_address):
            continue

        if "off_" in idc.print_operand(instructions[i], 1):
            string_length: int = idc.get_qword(source_address + 8)
            label: str = create_rust_string_label(idc.get_qword(source_address), string_length)
            idc.set_name(source_address, label)
            continue

def is_in_data_section(address: int) -> bool:
    segment = idaapi.get_visible_segm_name(idaapi.getseg(address))
    return segment == "_rodata" or segment == "_rdata" or segment == "_data_rel_ro"

def create_rust_string_label(address: int, length: int) -> str:
    label: str = "ra"

    if length > 24:
        length = 24

    for i in range(length):
        label += chr(idc.get_wide_byte(address + i))

    return label

def set_string_name(address: int, label: str) -> bool:
    if not label.isascii():
        return False
    
    idc.set_name(address, label)
    return True

def set_string_comment(address: int, label: str) -> bool:
    if not label.isascii():
        return False
    
    # TODO: third arg?
    idc.set_cmt(address, label, False)
    return True

