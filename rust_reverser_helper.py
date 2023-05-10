"""
import rust_reverser_helper_lib.helpers
import rust_reverser_helper_lib.rust_strings
import rust_reverser_helper_lib.disassembly_fixer
import rust_reverser_helper_lib.signature_fixer
import rust_reverser_helper_lib.rust_detection
"""

import helpers
import rust_strings
import disassembly_fixer
import signature_fixer
import rust_detection

import ida_auto
import idaapi
import ida_kernwin

"""
class ExecuteAll(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        
    def activate(self, ctx):
        #execute_all()
        print("hello")

class RustReverserHelper(idaapi.plugin_t):
    wanted_name = "Rust Reverser Helper"
    wanted_hotkey = "Alt-Shift-R"
    flags = idaapi.PLUGIN_UNL

    comment = "Detects strings, fixes disassembly and corrects function signatures for Rust binaries."
    help = "If you are unsure whether the binary is compiled in Rust, this plugin will detect that on run."

    def init(self):
        return idaapi.PLUGIN_OK
    
    def run(self, args):
        if ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "RustReverserHelper:ExecuteAll",
            "Execute all",
            ExecuteAll()
        )):
            print("Registered 'Execute all'.")
            if ida_kernwin.attach_action_to_menu("Edit/Plugins/Rust Reverser Helper", "RustReverserHelper:ExecuteAll", ida_kernwin.SETMENU_APP):
                print("Attached to menu.")
    
    def term(self):
        pass

def PLUGIN_ENTRY():
    return RustReverserHelper()
"""

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

        helpers.info_ex("The Rust Reverser Helper has finished running.")

if __name__ == "__main__":
    idaapi.require("helpers")
    idaapi.require("rust_strings")
    idaapi.require("disassembly_fixer")
    idaapi.require("signature_fixer")
    idaapi.require("rust_detection")

    reverser = RustReverserHelper()
    reverser.execute_all()

