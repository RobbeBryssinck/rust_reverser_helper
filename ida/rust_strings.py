import idautils
import idaapi
import idc
import ida_name
import ida_struct
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_typeinf

from typing import List

import helpers

defined_strings = []

# TODO: architecture independence (start with 32 vs 64 bit).
def identify_rust_strings():
    create_rust_string_type()

    for function_address in idautils.Functions():
        identify_rust_strings_in_function(function_address)
    
    defined_strings.clear()

def create_rust_string_type():
    id = ida_struct.get_struc_id("RustString")
    if id != -1:
        dialogue_result = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_CANCEL, "The RustString type already exists. Do you want to overwrite this type?")
        if dialogue_result == ida_kernwin.ASKBTN_YES:
            idc.del_struc(id)
        elif dialogue_result == ida_kernwin.ASKBTN_NO:
            return
        elif dialogue_result == ida_kernwin.ASKBTN_CANCEL:
            helpers.warn_and_exit()
    
    id = ida_struct.add_struc(-1, "RustString")
    struc = ida_struct.get_struc(id)

    tif = idaapi.tinfo_t()

    idc.add_struc_member(id, "data_ptr", ida_idaapi.BADADDR, ida_bytes.off_flag()|ida_bytes.FF_DATA|ida_bytes.FF_QWORD, 0, 8)
    ida_typeinf.parse_decl(tif, None, "char * data_ptr;", ida_typeinf.PT_TYP)
    ida_struct.set_member_tinfo(struc, ida_struct.get_member(struc, 0), 0, tif, 0)
    
    idc.add_struc_member(id, "length", ida_idaapi.BADADDR, (ida_bytes.FF_QWORD|ida_bytes.FF_DATA)&0xFFFFFFFF, -1, 8)
    ida_typeinf.parse_decl(tif, None, "unsigned __int64 length;", ida_typeinf.PT_TYP)
    ida_struct.set_member_tinfo(struc, ida_struct.get_member(struc, 8), 0, tif, 0)

def identify_rust_strings_in_function(function_address: str):
    instructions: List[int] = helpers.get_instructions_from_function(function_address)

    viable_list_length: int = len(instructions) - 2
    for i in range(viable_list_length):
        if idc.print_insn_mnem(instructions[i]) != "lea":
            continue

        source_address: int = idc.get_operand_value(instructions[i], 1)

        if not is_global_rust_string(source_address):
            continue

        if "off_" in idc.print_operand(instructions[i], 1):
            if is_global_rust_string_empty(source_address):
                define_rust_string(source_address, "raEmpty")
                continue

            string_length: int = idc.get_qword(source_address + 8)
            label: str = create_rust_string_label(idc.get_qword(source_address), string_length)
            define_rust_string(source_address, label)
            continue


def is_global_rust_string(address: int):
    if not is_in_data_section(address):
        return False

    if not is_in_data_section(idc.get_qword(address)):
        return False

    length: int = idc.get_qword(address + 8)

    if length == 0 and not is_global_rust_string_empty(address):
        return False

    data: int = idc.get_qword(address)

    for i in range(length):
        if not chr(idc.get_wide_byte(data + i)).isascii():
            return False

    return True

def is_global_rust_string_empty(address: int):
    # Empty strings in Rust point to themselves.
    return idc.get_qword(address) == address and idc.get_qword(address + 8) == 0

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

def define_rust_string(address: int, label: str) -> bool:
    if address in defined_strings:
        return False

    if set_string_name(address, label) == False:
        return False
    
    idc.SetType(address, "RustString")

    defined_strings.append(address)

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

def mutate_duplicate_label(label: str) -> str:
    for i in range(1024):
        new_label: str = label + "_" + str(i)
        if not does_label_exist(new_label):
            return new_label

    raise RuntimeError("Failed to find appropriate name for label: '" + label + "'")

def does_label_exist(label: str) -> bool:
    return idc.get_name_ea_simple(label) != 0xffffffffffffffff

def apply_rust_string_type(address: int):
    idc.SetType(address, "RustString")

if __name__ == "__main__":
    identify_rust_strings()

