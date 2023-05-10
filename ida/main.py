import idaapi

import rust_strings

if __name__ == "__main__":
    idaapi.require("rust_strings")
    rust_strings.identify_rust_strings()
