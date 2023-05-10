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
        self.function_symbols_by_address = {}
        for function_id, function in self.functionSymbols.items():
            self.function_symbols_by_address[function.virtualAddress] = function

    # TODO: maybe add checks like name checking to make sure enums are being detected properly?
    def is_rust_enum_multiple_return(self, enum_symbol):
        if enum_symbol.length > 16:
            return False
        
        type_length: int = 0
        first_variant: bool = True

        for variant in enum_symbol.fields[:-1]:
            variant_type_id: str = str(variant.underlyingTypeId)
            if not variant_type_id in self.typeSymbols:
                raise RuntimeError("Variant type id not found: {}".format(variant_type_id))
            variant_type = self.typeSymbols[variant_type_id]

            value_type_id: str = str(variant_type.fields[0].underlyingTypeId)
            if not value_type_id in self.typeSymbols:
                raise RuntimeError("Value type id not found: {}".format(value_type_id))
            value_type = self.typeSymbols[value_type_id]

            if value_type.fieldCount >= 2:
                return False

            core_type_id: str = str(value_type.fields[0].underlyingTypeId)
            if not core_type_id in self.typeSymbols:
                raise RuntimeError("Core type id not found: {}".format(core_type_id))
            core_type = self.typeSymbols[core_type_id]

            if core_type.fieldCount >= 2:
                return False

            if first_variant:
                type_length = core_type.length
                first_variant = False
                continue

            if type_length != core_type.length:
                return False

        return True

    def is_multiple_return(self, type_symbol):
        if type_symbol.type == 3 and "enum2$" in type_symbol.name:
            return self.is_rust_enum_multiple_return(type_symbol)
        
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

    def test_multiple_return_false_positives(self):
        for address in idautils.Functions():
            function_details = helpers.get_function_details(address)
            
            # TODO: change this
            if function_details.rettype.get_size() != 16:
                continue

            virtual_address = address - self.base

            if not virtual_address in self.function_symbols_by_address:
                continue
            function = self.function_symbols_by_address[virtual_address]

            return_type_id = str(function.returnTypeId)

            if not return_type_id in self.typeSymbols:
                continue
            type_symbol = self.typeSymbols[return_type_id]

            if type_symbol.name == "void":
                print("This should be multiple return, but is void instead: {}, {}, {}".format(function.id, hex(address), function.name))

            with self.subTest(msg="{}: {}, {}, {}".format(hex(address), function.id, function.name, return_type_id)):
                self.assertTrue(self.is_multiple_return(type_symbol))

if __name__ == "__main__":
    unittest.TextTestRunner().run(unittest.TestLoader().loadTestsFromTestCase(RustReverserTests))

