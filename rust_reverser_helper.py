import helpers
import rust_strings
import disassembly_fixer
import signature_fixer
import rust_detection
import rust_main_detector

import ida_auto
import idaapi
import ida_kernwin

class RustReverserHelper():
    def __init__(self):
        self.rust_strings = []
        self.fixed_functions = []

    def execute_all(self):
        message: str = ""
        if rust_detection.detect_rust():
            message = "This binary is most likely compiled in Rust. Do you want to run the rust analyzer?"
        else:
            message = "This binary does not seem to be compiled in Rust. Do you want to run the rust analyzer anyway?"

        dialogue_result = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_CANCEL, message)
        if dialogue_result != ida_kernwin.ASKBTN_YES:
            return
    
        print("Running full suite of the Rust Reverser Helper...")

        helpers.get_platform().init()

        self.fixed_functions = disassembly_fixer.fix_disassembly()
        ida_auto.auto_wait()
        self.rust_strings = rust_strings.identify_rust_strings()
        ida_auto.auto_wait()
        signature_fixer.fix_multiple_return_signatures()
        ida_auto.auto_wait()
        rust_main_address: int = rust_main_detector.detect_rust_main()
        if rust_main_address == 0:
            print("Rust main not detected.")
            helpers.info_ex("The Rust Reverser Helper has finished running. The RustMain function was not detected.\n\nBeware that Ida's decompiler has not fully refreshed the code at all call sites.\nIf you see unassigned local variables (variables in red), decompile the function twice (hit F5 twice).")
        else:
            print("Rust main detected at {}".format(rust_main_address))
            helpers.info_ex("The Rust Reverser Helper has finished running. The RustMain function was detected at address '{}'.\n\nBeware that Ida's decompiler has not fully refreshed the code at all call sites.\nIf you see unassigned local variables (variables in red), decompile the function twice (hit F5 twice).".format(hex(rust_main_address)))


if __name__ == "__main__":
    idaapi.require("helpers")
    idaapi.require("rust_strings")
    idaapi.require("disassembly_fixer")
    idaapi.require("signature_fixer")
    idaapi.require("rust_detection")
    idaapi.require("rust_main_detector")

    reverser = RustReverserHelper()
    reverser.execute_all()

