import os
import unittest
import json
from types import SimpleNamespace
import helpers
import rust_string_extractor
import rust_reverser_helper

import idaapi
import idautils
import ida_loader
import ida_hexrays
import ida_funcs
import ida_kernwin
import ida_nalt

reverser = rust_reverser_helper.RustReverserHelper()

class RustReverserTests(unittest.TestCase):
    def setUp(self):
        data = ""
        with open(ida_loader.get_path(ida_loader.PATH_TYPE_CMD).rsplit('.')[0] + ".json") as file:
            data = file.read()
        self.symbols = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
        self.base = idaapi.get_imagebase()
        self.typeSymbols = vars(self.symbols.typeSymbols)
        self.functionSymbols = vars(self.symbols.functionSymbols)
        self.function_symbols_by_address = {}
        for function_id, function in self.functionSymbols.items():
            self.function_symbols_by_address[function.virtualAddress] = function
    
    def unpack_typedef(self, type_symbol):
        while type_symbol.type == 7:
            type_symbol = self.typeSymbols[type_symbol.typedefSource]
        return type_symbol

    # TODO: maybe add checks like name checking to make sure enums are being detected properly?
    # What if a function returns a specific instance of an enum?
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
            
            # Empty enum options don't need checking
            if value_type.fieldCount == 0:
                continue

            core_type_id: str = str(value_type.fields[0].underlyingTypeId)
            if not core_type_id in self.typeSymbols:
                raise RuntimeError("Core type id not found: {}".format(core_type_id))
            core_type = self.typeSymbols[core_type_id]

            # Tuples are special, are returned as multiple return
            if "tuple$<" in core_type.name:
                return True

            if core_type.fieldCount >= 2:
                return False

            if first_variant:
                type_length = core_type.length
                first_variant = False
            elif type_length != core_type.length:
                return False

        return True
    
    def is_rust_option_multiple_return(self, enum_symbol):
        if enum_symbol.length > 16:
            return False
        
        if enum_symbol.fieldCount < 2:
            raise RuntimeError("This Option has no Some: {}".format(enum_symbol.id))
        
        some_type_id: str = str(enum_symbol.fields[1].underlyingTypeId)
        if not some_type_id in self.typeSymbols:
            raise RuntimeError("Some type id not found: {}".format(some_type_id))
        some_type = self.typeSymbols[some_type_id]
        
        value_type_id: str = str(some_type.fields[0].underlyingTypeId)
        if not value_type_id in self.typeSymbols:
            raise RuntimeError("Value type id not found: {}".format(value_type_id))
        value_type = self.typeSymbols[value_type_id]

        # Tuples are special, are returned as multiple return
        if "tuple$<" in value_type.name:
            return True
        
        if value_type.fieldCount >= 2:
            return False
        
        # TODO: test this
        if value_type.fieldCount == 0:
            return True
        
        core_type_id: str = str(value_type.fields[0].underlyingTypeId)
        if not core_type_id in self.typeSymbols:
            raise RuntimeError("Core type id not found: {}".format(core_type_id))
        core_type = self.typeSymbols[core_type_id]

        if core_type.fieldCount >= 2:
            return False

        return True

    def is_multiple_return(self, type_symbol):
        # Result is an extra special case
        if type_symbol.type == 3 and type_symbol.length == 16 and "enum2$<core::result::Result<" in type_symbol.name:
            return True
        
        if type_symbol.type == 3 and "enum2$<core::option::Option<" in type_symbol.name:
            try:
                return self.is_rust_option_multiple_return(type_symbol)
            except:
                self.assertTrue(False, msg="is_rust_option_multiple_return failure {}".format(type_symbol.name))
        elif type_symbol.type == 3 and "enum2$" in type_symbol.name:
            try:
                return self.is_rust_enum_multiple_return(type_symbol)
            except:
                self.assertTrue(False, msg="is_rust_enum_multiple_return failure {}".format(type_symbol.name))
            
        union_id_to_length = {}

        real_field_count = type_symbol.fieldCount

        size: int = 0
        for field in type_symbol.fields:
            field_length = 0
            underlying_type = self.typeSymbols[str(field.underlyingTypeId)]
            
            if field.isAnonymousUnion:
                if not str(field.unionId) in union_id_to_length:
                    union_id_to_length[str(field.unionId)] = underlying_type.length
                else:
                    real_field_count = real_field_count - 1
                    union_length = union_id_to_length[str(field.unionId)]
                    if underlying_type.length > union_length:
                        union_id_to_length[str(field.unionId)] = underlying_type.length
                    continue
                
                field_length = union_id_to_length[str(field.unionId)]
            else:
                field_length = underlying_type.length
            
            size = size + field_length
        
        # MRR is only valid with one 128-bit members or two members smaller than 128 bits combined.
        if real_field_count == 0 or real_field_count > 2:
            return False
        
        print("Return type: {}, size: {}".format(type_symbol.id, size))

        if size == 0 or size > 16:
            return False

        if type_symbol.fieldCount == 1 and size <= 8:
            return False
        
        return True

    def test_multiple_return_false_negatives(self):
        for function_id, function in self.functionSymbols.items():
            return_type_id = str(function.returnTypeId)
            
            if not return_type_id in self.typeSymbols:
                continue
            type_symbol = self.typeSymbols[return_type_id]

            if type_symbol.type == 7:
                type_symbol = self.unpack_typedef(type_symbol)

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

            if type_symbol.type == 7:
                type_symbol = self.unpack_typedef(type_symbol)

            # This takes away most of the "false" false positives, but beware that some real false positives slip through.
            if type_symbol.name == "void":
                print("This should be multiple return, but is void instead: {}, {}, {}".format(function.id, hex(address), function.name))
                continue

            with self.subTest(msg="{}: {}, {}, {}".format(hex(address), function.id, function.name, return_type_id)):
                self.assertTrue(self.is_multiple_return(type_symbol))
    
    def test_rust_user_defined_strings_false_negatives(self):
        ida_kernwin.info("Input the Rust source directory in the following form, or press 'cancel' to skip the string tests.")

        while True:
            source_directory = ida_kernwin.ask_str("", 0, "")

            if source_directory == None:
                print("Cancelling rust string tests.")
                return

            if not os.path.isdir(source_directory):
                if not os.path.exists(source_directory):
                    ida_kernwin.warning("Directory '{}' does not exist.".format(source_directory))
                else:
                    ida_kernwin.warning("Path '{}' is not a directory.".format(source_directory))
                continue

            break

        string_extractor = rust_string_extractor.RustStringExtractor()
        string_extractor.extract_strings_from_files(source_directory)

        for rust_string in string_extractor.strings:
            with self.subTest(msg="Rust string: {}".format(rust_string)):
                if rust_string in reverser.rust_strings:
                    self.assertTrue(True)
                else:
                    # Rust's `println!()` macros adds a newline, which the string extractor does not account for.
                    rust_string = rust_string + "\n"
                    self.assertIn(rust_string, reverser.rust_strings)
    
    def test_disassembly_fixes(self):
        for fixed_function in reverser.fixed_functions:
            with self.subTest("Function fix check: {}".format(hex(fixed_function))):
                func = ida_funcs.get_func(fixed_function)
                func_failure = ida_hexrays.hexrays_failure_t()
                result = ida_hexrays.decompile_func(func, func_failure)

                critical_warning_hit: bool = False

                for warning in result.get_warnings():
                    if warning.id == 43:
                        critical_warning_hit = True
                        break
                
                self.assertFalse(critical_warning_hit, "Function is not fixed: {}".format(hex(fixed_function)))

if __name__ == "__main__":
    idaapi.require("helpers")
    idaapi.require("rust_strings")
    idaapi.require("disassembly_fixer")
    idaapi.require("signature_fixer")
    idaapi.require("rust_detection")
    idaapi.require("rust_reverser_helper")

    file_path = ida_nalt.get_input_file_path()
    file_base_name = os.path.basename(file_path).split('.')[-2]
    usym_file_path = os.getcwd() + "/" + file_base_name + ".json"

    if not os.path.exists(usym_file_path):
        ida_kernwin.warning("USYM file '{}' does not exist. Did you run the Universal Symbol conversion tool?".format(usym_file_path))

    reverser.execute_all()
    unittest.TextTestRunner().run(unittest.TestLoader().loadTestsFromTestCase(RustReverserTests))

