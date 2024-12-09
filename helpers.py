import idc
import ida_kernwin
import idaapi
import ida_auto
import ida_hexrays
import ida_funcs
import ida_nalt

from typing import List
from enum import Enum

def warn_and_exit():
    ida_kernwin.warning("The Rust reverser helper has stopped early.")
    exit()

def info_ex(message: str):
    print(message)
    ida_kernwin.info(message)

def get_instructions_from_function(function_address: int) -> List[int]:
    instructions: List[int] = []
    current_instruction: int = function_address

    function_end_address: int = idc.find_func_end(function_address)

    while current_instruction < function_end_address:
        instructions.append(current_instruction)
        current_instruction = idc.find_code(current_instruction, idc.SEARCH_DOWN)
    
    return instructions

def decompile_function(func_start: int):
    hf = ida_hexrays.hexrays_failure_t()
    ida_hexrays.decompile_func(ida_funcs.get_func(func_start), hf)

    ida_auto.auto_wait()

def get_function_details(address: int):
    function_tinfo = idaapi.tinfo_t()
    ida_nalt.get_tinfo(function_tinfo, address)
    
    function_details = idaapi.func_type_data_t()
    function_tinfo.get_func_details(function_details)

    return function_details

class Platform():
    class FileFormat(Enum):
        NONE = 0
        ELF = 1
        PE = 2
    
    class Architecture(Enum):
        NONE = 0
        X86 = 1
        X64 = 2
        ARM32 = 3
        ARM64 = 4

    # TODO: this static init stuff is bad, what if idb is changed, for example?
    def __init__(self):
        self.file_format = Platform.FileFormat.NONE
        self.architecture = Platform.Architecture.NONE
        self.platform = (self.file_format, self.architecture)

    def init(self):
        platform_type: str = idaapi.get_file_type_name().lower()

        if "pe" in platform_type:
            self.file_format = Platform.FileFormat.PE
        elif "elf" in platform_type:
            self.file_format = Platform.FileFormat.ELF

        if "64" in platform_type:
            if "amd64" in platform_type or "x86" in platform_type:
                self.architecture = Platform.Architecture.X64
            elif "arm" in platform_type:
                self.architecture = Platform.Architecture.ARM64
        elif "32" in platform_type:
            if "x86" in platform_type:
                self.architecture = Platform.Architecture.X86
            elif "arm" in platform_type:
                self.architecture = Platform.Architecture.ARM32

        self.platform = (self.file_format, self.architecture)

        proven_combinations = [
            (Platform.FileFormat.PE, Platform.Architecture.X64),
            (Platform.FileFormat.ELF, Platform.Architecture.X64),
            (Platform.FileFormat.ELF, Platform.Architecture.ARM64),
        ]

        if self.file_format == Platform.FileFormat.NONE or self.architecture == Platform.Architecture.NONE or self.platform not in proven_combinations:
            print(f"Architecture is not supported yet: '{platform_type}'.")
            warn_and_exit()
    
    def is_intel_x86(self) -> bool:
        return self.architecture == Platform.Architecture.X64 or self.architecture == Platform.Architecture.X86

    def is_x64(self) -> bool:
        return self.architecture == Platform.Architecture.X64
    
    def is_x86(self) -> bool:
        return self.architecture == Platform.Architecture.X86

    def is_arm(self) -> bool:
        return self.architecture == Platform.Architecture.ARM64 or self.architecture == Platform.Architecture.ARM32
    
    def is_arm64(self) -> bool:
        return self.architecture == Platform.Architecture.ARM64

    def is_arm32(self) -> bool:
        return self.architecture == Platform.Architecture.ARM32

    def is_pe_x64(self) -> bool:
        return self.platform == (Platform.FileFormat.PE, Platform.Architecture.X64)
    
    def is_elf_x64(self) -> bool:
        return self.platform == (Platform.FileFormat.ELF, Platform.Architecture.X64)
    
    def is_64_bit(self) -> bool:
        return self.architecture == Platform.Architecture.X64 or self.architecture == Platform.Architecture.ARM64

def get_platform() -> Platform:
    return get_platform.platform

get_platform.platform: Platform = Platform()

def is_second_return_reg_in_operand(address: int, position: int) -> bool:
    platform = get_platform()

    operand: str = idc.print_operand(address, position)

    if operand == "":
        return False

    if platform.is_intel_x86():
        if "+rdx" in operand or "+edx" in operand or "+dx" in operand or "+dl" in operand:
            return False
        
        return "rdx" in operand or "edx" in operand or "dx" in operand or "dl" in operand
    else:
        return False

def is_moving_instruction(address: int) -> bool:
    platform = get_platform()

    operator: str = idc.print_insn_mnem(address)

    if platform.is_intel_x86():
        return "mov" in operator
    else:
        return False

def is_calling_instruction(address: int) -> bool:
    platform = get_platform()

    operator: str = idc.print_insn_mnem(address)

    if platform.is_intel_x86():
        return operator == "call"
    else:
        return False

def is_returning_instruction(address: int) -> bool:
    platform = get_platform()

    operator: str = idc.print_insn_mnem(address)

    if platform.is_intel_x86():
        return operator == "retn"
    else:
        return False

def get_multiple_return_size() -> int:
    if get_platform().is_64_bit():
        return 16
    else:
        return 8

def is_jump(address: int) -> bool:
    platform = get_platform()

    operator: str = idc.print_insn_mnem(address)

    if platform.is_intel_x86():
        return operator == "jmp"
    else:
        return False

def is_jump_outside(address: int, function_start: int, function_end: int) -> bool:
    platform = get_platform()

    operator: str = idc.print_insn_mnem(address)
    operand: str = idc.print_operand(address, 0)

    if platform.is_intel_x86():
        if operator != "jmp":
            return False

        if operand == "rax" or operand == "eax":
            return True

        destination: int = idc.get_operand_value(address, 0)
        return destination < function_start or destination > function_end
    else:
        return False

def is_jump_dynamic(address: int) -> bool:
    platform = get_platform()

    operator: str = idc.print_insn_mnem(address)
    operand: str = idc.print_operand(address, 0)

    if platform.is_intel_x86():
        if operator != "jmp":
            return False

        return operand == "rax" or operand == "eax"
    else:
        return False

def is_load_address_instruction(address: int) -> bool:
    return idc.print_insn_mnem(address) == get_load_address_instruction()

def get_load_address_instruction() -> str:
    platform = get_platform()

    if platform.is_intel_x86():
        return "lea"
    elif platform.is_arm():
        return "ADRL"
    else:
        return ""

def get_first_argument_register() -> str:
    platform = get_platform()

    if platform.is_x64():
        return "rcx"
    elif platform.is_x86():
        return "ecx"
    else:
        return ""

