import idc
import idautils
import ida_bytes
import ida_ua
import ida_funcs
import ida_idaapi
import ida_problems

from typing import List

def fix_disassembly():
    reanalyze_all_functions()

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

