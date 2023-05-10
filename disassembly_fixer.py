import idc
import idautils
import ida_bytes
import ida_ua
import ida_funcs
import ida_auto
import ida_problems
import ida_hexrays

from typing import List

import helpers

# TODO: maybe decompile all again after fixing all functions?

problematic_functions = []

def fix_disassembly() -> List[int]:
    problematic_functions.clear()
    
    reanalyze_problematic_functions()

    ida_auto.auto_wait()

    return problematic_functions

def get_problematic_functions() -> List[int]:
    for function_address in idautils.Functions():
        if is_function_problematic(function_address):
            problematic_functions.append(function_address)
    
    return problematic_functions

def is_function_problematic(ea: int) -> bool:
    func_end = idc.find_func_end(ea)
    ptype = ida_problems.PR_DISASM
    
    ea = ida_problems.get_problem(ptype, ea+1)
    
    if ea > func_end:
        return False  
    
    return True

def reanalyze_problematic_functions():
    for function in get_problematic_functions():
        reanalyze_function(function)

def reanalyze_all_functions():
    for function_address in idautils.Functions():
        reanalyze_function(function_address)

def reanalyze_function(func_start: int):
    func_end = idc.find_func_end(func_start)
    size = func_end - func_start

    ida_bytes.del_items(func_start, 0, size)

    for i in range(size):
        ida_ua.create_insn(func_start + i)

    ida_funcs.add_func(func_start, func_end)
    
    ida_auto.auto_wait()

    helpers.decompile_function(func_start)

    print("Fixed function {}".format(hex(func_start)))

    reset_problems_in_function(func_start, func_end)

# There's a bug in Ida's API.
# If you undefine and redefine a function's data, the operands are marked as a disassembly problem.
# This resets each problem in the reanalyzed functions.
def reset_problems_in_function(func_start: int, func_end: int):
    current_address: int = func_start
    while current_address != func_end:
        ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
        current_address = current_address + 1

def verify_functions():
    problematic_functions = get_problematic_functions()
    if not problematic_functions:
        print("No problematic functions detected.")
    else:
        print("The following problematic functions were detected:")
        for function in problematic_functions:
            print("\t* 0x%08x" % function)

if __name__ == "__main__":
    fix_disassembly()
