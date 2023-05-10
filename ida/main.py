import idaapi

import rust_strings
import helpers

if __name__ == "__main__":
    idaapi.require("rust_strings")
    idaapi.require("helpers")
    rust_strings.identify_rust_strings()
