import helpers
import rust_strings
import disassembly_fixer
import signature_fixer
import rust_detection

import ida_auto
import idaapi
import ida_kernwin

def execute_all():
    print("Running full suite of the Rust Reverser Helper...")

    disassembly_fixer.fix_disassembly()
    ida_auto.auto_wait()
    rust_strings.identify_rust_strings()
    ida_auto.auto_wait()
    signature_fixer.fix_multiple_return_signatures()
    ida_auto.auto_wait()

    print("The Rust Reverser Helper has finished running.")

if __name__ == "__main__":
    idaapi.require("helpers")
    idaapi.require("rust_strings")
    idaapi.require("disassembly_fixer")
    idaapi.require("signature_fixer")
    idaapi.require("rust_detection")

    if rust_detection.detect_rust():
        dialogue_result = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_CANCEL, "This binary is most likely compiled in Rust. Do you want to run the rust analyzer?")
        if dialogue_result == ida_kernwin.ASKBTN_YES:
            execute_all()
        else:
            helpers.warn_and_exit()

