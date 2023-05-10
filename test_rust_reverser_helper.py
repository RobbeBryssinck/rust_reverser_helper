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

        self.functions_by_virtual_address = {}
        for function in self.symbols.functionSymbols:
            self.functions_by_virtual_address[function.virtualAddress] = function
        
        self.types_by_id = {}
        for type in self.symbols.typeSymbols:
            self.types_by_id[type.id] = type

    def test_multiple_return_false_negatives(self):
        for function in self.symbols.functionSymbols:
            return_type_id = function.returnTypeId
            for type in self.symbols.typeSymbols:
                if type.id != return_type_id:
                    continue

                if type.length <= 8 or type.length > 16:
                    continue
                
                address = self.base + function.virtualAddress
                function_details = helpers.get_function_details(address)

                with self.subTest(msg="{}: {}, {}".format(hex(address), function.id, function.name)):
                    self.assertEqual(function_details.rettype.get_size(), 16)

    def test_multiple_return_false_positives(self):
        for address in idautils.Functions():
            function_details = helpers.get_function_details(address)
            
            if function_details.rettype.get_size() != 16:
                continue

            virtual_address = address - self.base

            for function in self.symbols.functionSymbols:
                if function.virtualAddress != virtual_address:
                    continue

                return_type_id = function.returnTypeId
                for type in self.symbols.typeSymbols:
                    if type.id != return_type_id:
                        continue
                    with self.subTest(msg="{}: {}, {}".format(hex(address), function.id, function.name)):
                        self.assertTrue(type.length > 8 and type.length <= 16, "{}: {}".format(hex(address), function.id))


if __name__ == "__main__":
    unittest.TextTestRunner().run(unittest.TestLoader().loadTestsFromTestCase(RustReverserTests))

