import idc
import idautils
import ida_bytes
import ida_ua
import ida_funcs
import ida_auto
import ida_problems

from typing import List

def fix_disassembly():
    reanalyze_problematic_functions()

    ida_auto.auto_wait()

def get_problematic_functions() -> List[int]:
    problematic_functions = []

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
    problematic_functions = get_problematic_functions()
    for function in problematic_functions:
        reanalyze_function(function)

def reanalyze_all_functions():
    for function_address in idautils.Functions():
        reanalyze_function(function_address)

# TODO: cleaner way maybe, to retain function name (ida_funcs api), or warn about it before running?
def reanalyze_function(func_start: int):
    func_end = idc.find_func_end(func_start)
    size = func_end - func_start

    ida_bytes.del_items(func_start, 0, size)

    for i in range(size):
        ida_ua.create_insn(func_start + i)

    ida_funcs.add_func(func_start, func_end)

# TODO: there's a bug in Ida's API.
# If you undefine and redefine a function's data, the operands are marked as a disassembly problem.
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
