import idautils
import idaapi
import idc
import ida_name

from typing import List

import helpers

# TODO: expand this (or better yet, find an Ida api function that does this).
def is_register_name(label: str) -> bool:
    return label == "rax"

# TODO: architecture independence (start with 32 vs 64 bit).
def identify_rust_strings():
    for function_address in idautils.Functions():
        identify_rust_strings_in_function(function_address)

def is_global_rust_string(address: int):
    if not is_in_data_section(address):
        return False

    length: int = idc.get_qword(address + 8)

    # TODO: these heuristics are wrong, the compiler makes no such guarantees.
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

        source_address: int = idc.get_operand_value(instructions[i], 1)
        if not is_in_data_section(source_address):
            continue

        if "off_" in idc.print_operand(instructions[i], 1):
            if is_global_rust_string_empty(instructions[i]):
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
        character: str = chr(idc.get_wide_byte(address + i))
        if i == 0 and character.isalpha():
            character = character.upper()
        label += character

    # Use "2" as flag here for valid string label names.
    label = ida_name.validate_name(label, 2)

    return label

# TODO: map that marks addresses that have been labeled already?
def set_string_name(address: int, label: str) -> bool:
    if not label.isascii():
        return False

    if does_label_exist(label):
        label = mutate_duplicate_label(label)

    result: bool = idc.set_name(address, label)

    if result == False:
        raise RuntimeError("Failed to name string at " + hex(address) + ": '" + label + "'")

    print("Successfully placed label at " + hex(address) + ": '" + label + "'")

    return True

# TODO: map that marks addresses that have been commented already?
def set_string_comment(address: int, label: str) -> bool:
    if not label.isascii():
        return False

    if does_label_exist(label):
        label = mutate_duplicate_label(label)

    # TODO: third arg?
    result: bool = idc.set_cmt(address, label, False)

    if result == False:
        raise RuntimeError("Failed to place comment: '" + label + "'")

    print("Successfully placed comment: '" + label + "'")

    return True

# TODO: handle exception.
def mutate_duplicate_label(label: str) -> str:
    for i in range(1024):
        new_label: str = label + "_" + chr(i)
        if not does_label_exist(new_label):
            return new_label

    raise RuntimeError("Failed to find appropriate name for label: '" + label + "'")

def does_label_exist(label: str) -> bool:
    return idc.get_name_ea_simple(label) != 0xffffffffffffffff

