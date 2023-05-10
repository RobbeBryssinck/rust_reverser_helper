import idc
import ida_kernwin
import idaapi

from typing import List
from enum import Enum

def warn_and_exit():
    ida_kernwin.warning("The Rust reverser helper has stopped early.")
    exit()

def get_instructions_from_function(function_address: int) -> List[int]:
    instructions: List[int] = []
    current_instruction: int = function_address

    function_end_address: int = idc.find_func_end(function_address)

    while current_instruction < function_end_address:
        instructions.append(current_instruction)
        current_instruction = idc.find_code(current_instruction, idc.SEARCH_DOWN)
    
    return instructions

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

    def __init__(self):
        platform_type: str = idaapi.get_file_type_name().lower()
        self.file_format = Platform.FileFormat.NONE
        self.architecture = Platform.Architecture.NONE

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
                self.architecture = Platform.Architecture.X32
            elif "arm" in platform_type:
                self.architecture = Platform.Architecture.ARM32

        self.platform = (self.file_format, self.architecture)

        proven_combinations = [
            (Platform.FileFormat.PE, Platform.Architecture.X64),
            (Platform.FileFormat.ELF, Platform.Architecture.X64),
            (Platform.FileFormat.ELF, Platform.Architecture.ARM64),
        ]

        if self.file_format == Platform.FileFormat.NONE or self.architecture == Platform.Architecture.NONE or self.platform not in proven_combinations:
            print("Architecture is not supported yet: '{}'.".format(platform_type))
            warn_and_exit()
    
    def is_pe_x64(self) -> bool:
        return self.platform == (Platform.FileFormat.PE, Platform.Architecture.X64)
    
    def is_elf_x64(self) -> bool:
        return self.platform == (Platform.FileFormat.ELF, Platform.Architecture.X64)
    
    # ARM has the same ABI across different operating systems.
    def is_arm64(self) -> bool:
        return self.architecture == Platform.Architecture.ARM64

def get_platform() -> Platform:
    return get_platform.platform

get_platform.platform: Platform = Platform()

