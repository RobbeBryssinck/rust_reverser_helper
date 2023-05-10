import idc

from typing import List

def get_instructions_from_function(function_address: int) -> List[int]:
    instructions: List[int] = []
    current_instruction: int = function_address

    function_end_address: int = idc.find_func_end(function_address)

    while current_instruction < function_end_address:
        instructions.append(current_instruction)
        current_instruction = idc.find_code(current_instruction, idc.SEARCH_DOWN)
    
    return instructions

