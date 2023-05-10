import idautils
import idaapi
import idc
import ida_name
import ida_struct
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_typeinf
import ida_name

from typing import List

import helpers

defined_strings = []

def identify_rust_strings():
    create_rust_string_type()

    for function_address in idautils.Functions():
        if not identify_rust_strings_in_function(function_address):
            defined_strings.clear()
            return
    
    defined_strings.clear()

def create_rust_string_type():
    id = ida_struct.get_struc_id("RustString")
    if id != ida_idaapi.BADADDR:
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

def identify_rust_strings_in_function(function_address: str) -> bool:
    instructions: List[int] = helpers.get_instructions_from_function(function_address)

    # TODO: move to helpers
    load_instruction: str = ""
    if helpers.get_platform().is_arm():
        load_instruction = "ADRL"
    elif helpers.get_platform().is_intel_x86():
        load_instruction = "lea"
    else:
        # TODO: move this to identify_rust_strings()
        print("Architecture is not supported (has no load instruction for strings).")
        return False

    viable_list_length: int = len(instructions) - 2
    for i in range(viable_list_length):
        if idc.print_insn_mnem(instructions[i]) != load_instruction:
            continue

        source_address: int = idc.get_operand_value(instructions[i], 1)

        if is_global_rust_string(source_address):
            if is_global_rust_string_empty(source_address):
                define_global_rust_string(source_address, "raEmpty")
                continue

            string_length: int = idc.get_qword(source_address + 8)
            label: str = create_global_rust_string_label(idc.get_qword(source_address), string_length)
            define_global_rust_string(source_address, label)
        elif is_inline_rust_string(instructions[i:(i+3)]):
            lea, mov_data, mov_len = instructions[i:(i+3)]

            string_address: int = idc.get_operand_value(lea, 1)
            string_length: int = idc.get_operand_value(mov_len, 1)
            label: str = create_inline_rust_string_label(string_address, string_length)
            define_inline_rust_string(string_address, label)
    
    return True

def is_global_rust_string(address: int) -> bool:
    if not is_in_data_section(address):
        return False

    if not is_in_data_section(idc.get_qword(address)):
        return False
    
    if not "off_" in ida_name.get_ea_name(address):
        return False

    length: int = idc.get_qword(address + 8)

    if length == 0 and not is_global_rust_string_empty(address):
        return False

    data: int = idc.get_qword(address)

    return is_valid_ascii_string(data, length)

def is_global_rust_string_empty(address: int) -> bool:
    # Empty strings in Rust point to themselves.
    return idc.get_qword(address) == address and idc.get_qword(address + 8) == 0

def is_inline_rust_string(instructions: List[int]) -> bool:
    if len(instructions) != 3:
        return False
    
    lea, mov_data, mov_len = instructions
    
    source_address: int = idc.get_operand_value(lea, 1)
    if not is_in_data_section(source_address):
        return False
    
    if not "unk_" in idc.print_operand(lea, 1):
        return False
    
    # The assembly layout of an inline instruction looks as follows:
    #
    # lea rax, unk_XXXXXX
    # mov qword ptr [rbp + XXh + var_a], rax
    # mov qword ptr [rbp + XXh + var_a + 8], len

    # TODO: move lea to helpers
    if idc.print_insn_mnem(lea) != "lea" or not helpers.is_moving_instruction(mov_data) or not helpers.is_moving_instruction(mov_len):
        return False

    if idc.get_operand_type(lea, 0) != idc.o_reg or idc.get_operand_type(mov_data, 0) != idc.o_displ or idc.get_operand_type(mov_len, 0) != idc.o_displ or idc.get_operand_type(mov_len, 1) != idc.o_imm:
        return False

    if idc.print_operand(lea, 0) != idc.print_operand(mov_data, 1):
        return False
    
    if (idc.get_operand_value(mov_len, 0) - idc.get_operand_value(mov_data, 0)) != 8:
        return False
    
    length: int = idc.get_operand_value(mov_len, 1)
    if length == 0:
        return False

    return is_valid_ascii_string(source_address, length)
    
def is_valid_ascii_string(data: int, length: int) -> bool:
    for i in range(length):
        if not chr(idc.get_wide_byte(data + i)).isprintable():
            return False
    
    return True

def is_in_data_section(address: int) -> bool:
    segment = idaapi.get_visible_segm_name(idaapi.getseg(address))
    return segment == "_rodata" or segment == "_rdata" or segment == "_data_rel_ro" or segment == ".rodata" or segment == ".rdata" or segment == ".data.rel.ro"

def create_global_rust_string_label(address: int, length: int) -> str:
    return create_rust_string_label("ra", address, length)

def create_inline_rust_string_label(address: int, length: int) -> str:
    return create_rust_string_label("ia", address, length)

def create_rust_string_label(prefix: str, address: int, length: int) -> str:
    label: str = prefix

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

def define_global_rust_string(address: int, label: str) -> bool:
    result: bool = define_rust_string(address, label)
    
    if result == True:
        idc.SetType(address, "RustString")
    
    return result

def define_inline_rust_string(address: int, label: str) -> bool:
    return define_rust_string(address, label)

def define_rust_string(address: int, label: str) -> bool:
    if address in defined_strings:
        return False

    if set_string_name(address, label) == False:
        return False

    defined_strings.append(address)

    return True

def set_string_name(address: int, label: str) -> bool:
    if not label.isprintable():
        return False

    if does_label_exist(label):
        try:
            label = mutate_duplicate_label(label)
        except RuntimeError as e:
            print(e.args[0])
            return False

    result: bool = idc.set_name(address, label)

    if result:
        print("Successfully placed label at " + hex(address) + ": '" + label + "'")
    else:
        print("Failed to name string at " + hex(address) + ": '" + label + "'")

    return result

def set_string_comment(address: int, label: str) -> bool:
    if not label.isprintable():
        return False

    if does_label_exist(label):
        try:
            label = mutate_duplicate_label(label)
        except RuntimeError as e:
            print(e.args[0])
            return False

    # TODO: third arg?
    result: bool = idc.set_cmt(address, label, False)

    if result:
        print("Successfully placed comment: '" + label + "'")
    else:
        print("Failed to place comment: '" + label + "'")
    
    return result

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
    idaapi.require("helpers")
    identify_rust_strings()

