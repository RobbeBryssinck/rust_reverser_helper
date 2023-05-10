import idautils
import idaapi
import idc

from typing import List

import helpers

# TODO: architecture independence (start with 32 vs 64 bit)
def identify_rust_strings():
    for function_address in idautils.Functions():
        identify_rust_strings_in_function(function_address)

def is_global_rust_string(address: int):
    if not is_in_data_section(address):
        return False

    length: int = idc.get_qword(address + 8)

    # Global Rust strings should have the string data right before the str structure.
    # It is possible that the compiler injects padding for 8-byte alignment.
    string_address: int = idc.get_qword(address)
    padding: int = address - string_address - length
    if padding < 0 or padding >= 8:
        return False

    for i in range(length):
        if not chr(idc.get_wide_byte(address + i)).isascii():
            return False

    return True

def is_global_rust_string_empty(address: int):
    # Empty strings in Rust point to themselves.
    return idc.get_qword(address) == address and idc.get_qword(address + 8) == 0

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
            if is_global_rust_string_empty():
                set_string_name(source_address, "raEmpty")
                continue

            string_length: int = idc.get_qword(source_address + 8)
            label: str = create_rust_string_label(idc.get_qword(source_address), string_length)
            set_string_name(source_address, label)
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

# TODO: map that marks addresses that have been labeled already?
def set_string_name(address: int, label: str) -> bool:
    if not label.isascii():
        return False
    
    idc.set_name(address, label)
    return True

# TODO: map that marks addresses that have been commented already?
def set_string_comment(address: int, label: str) -> bool:
    if not label.isascii():
        return False
    
    # TODO: third arg?
    idc.set_cmt(address, label, False)
    return True

