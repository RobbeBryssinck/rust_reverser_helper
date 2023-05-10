import unittest
import json
from types import SimpleNamespace
import helpers

import idaapi
import idautils

class RustReverserTests(unittest.TestCase):
    def setUp(self):
        data = ""
        with open("rust_sample.json") as file:
            data = file.read()
        self.symbols = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
        self.base = idaapi.get_imagebase()
        self.typeSymbols = vars(self.symbols.typeSymbols)
        self.functionSymbols = vars(self.symbols.functionSymbols)

    def is_multiple_return(self, type_symbol):
        # MRR is only valid with one 128-bit members or two members smaller than 128 bits combined.
        if type_symbol.memberVariableCount > 2 or type_symbol.memberVariableCount == 0:
            return False
        
        size: int = 0
        for member_id in type_symbol.memberVariableIds:
            member_id_str: str = str(member_id)
            if member_id_str in self.typeSymbols:
                size = size + self.typeSymbols[member_id_str].length
        
        print("Return type: {}, size: {}".format(type_symbol.id, size))

        if size == 0:
            return False

        if type_symbol.memberVariableCount == 1 and size <= 8:
            return False
        
        if type_symbol.memberVariableCount == 2 and size > 16:
            return False
        
        return True

    def test_multiple_return_false_negatives(self):
        for function_id, function in self.functionSymbols.items():
            return_type_id = str(function.returnTypeId)
            
            if not return_type_id in self.typeSymbols:
                continue
            type_symbol = self.typeSymbols[return_type_id]

            if not self.is_multiple_return(type_symbol):
                continue

            address = self.base + function.virtualAddress
            function_details = helpers.get_function_details(address)

            print("This should be multiple return: {} {}".format(function_id, hex(address)))

            with self.subTest(msg="{}: {}, {}".format(hex(address), function_id, function.name)):
                self.assertEqual(function_details.rettype.get_size(), 16)

"""
    def test_multiple_return_false_positives(self):
        for address in idautils.Functions():
            function_details = helpers.get_function_details(address)
            
            if function_details.rettype.get_size() != 16:
                continue

            virtual_address = address - self.base

            if not virtual_address in self.functionSymbols:
                continue
            function = self.functionSymbols[virtual_address]

            return_type_id = function.returnTypeId

            if not return_type_id in self.typeSymbols:
                continue
            type_symbol = self.typeSymbols[return_type_id]

            with self.subTest(msg="{}: {}, {}".format(hex(address), function.id, function.name)):
                self.assertTrue(self.is_multiple_return(type_symbol))
"""

if __name__ == "__main__":
    unittest.TextTestRunner().run(unittest.TestLoader().loadTestsFromTestCase(RustReverserTests))

