import idautils
import idaapi
import ida_funcs
import idc

import helpers

from typing import List

def detect_rust_main() -> int:
    rust_main_address: int = 0

    c_main_address: int = 0
    function_addresses = set()

    for function_address in idautils.Functions():
        if ida_funcs.get_func_name(function_address) == "main":
            c_main_address = function_address
        
        function_addresses.add(function_address)
    
    if c_main_address == 0:
        return 0
    
    instructions: List[int] = helpers.get_instructions_from_function(c_main_address)

    load_instruction: str = helpers.get_load_address_instruction()
    first_argument_register: str = helpers.get_first_argument_register()

    for instruction in instructions:
        if idc.print_insn_mnem(instruction) != load_instruction:
            continue

        if idc.print_operand(instruction, 0) != first_argument_register:
            continue

        if idc.get_operand_value(instruction, 1) not in function_addresses:
            continue

        rust_main_address = idc.get_operand_value(instruction, 1)
        idc.set_name(rust_main_address, "RustMain")
        
        break

    return rust_main_address


if __name__ == "__main__":
    idaapi.require("helpers")

    rust_main_address: int = detect_rust_main()

