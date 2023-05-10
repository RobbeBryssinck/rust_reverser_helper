import idaapi

import helpers
import rust_strings
import disassembly_fixer

if __name__ == "__main__":
    idaapi.require("helpers")
    idaapi.require("rust_strings")
    idaapi.require("disassembly_fixer")

    disassembly_fixer.fix_disassembly()
    rust_strings.identify_rust_strings()

