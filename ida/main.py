import idaapi

import helpers
import rust_strings
import disassembly_fixer
import signature_fixer

import ida_auto

if __name__ == "__main__":
    idaapi.require("helpers")
    idaapi.require("rust_strings")
    idaapi.require("disassembly_fixer")
    idaapi.require("signature_fixer")

    print("Running full suite of the Rust Reverser Helper...")

    disassembly_fixer.fix_disassembly()
    ida_auto.auto_wait()
    rust_strings.identify_rust_strings()
    ida_auto.auto_wait()
    signature_fixer.fix_multiple_return_signatures()
    ida_auto.auto_wait()

    print("The Rust Reverser Helper has finished running.")

