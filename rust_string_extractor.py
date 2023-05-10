import sys
import os
import glob
import re

class RustStringExtractor():
    def __init__(self):
        self.strings = []
    
    def extract_strings_from_files(self, rust_source_dir):
        for filename in glob.iglob(rust_source_dir + "**/*.rs", recursive=True):
            self.extract_strings_from_file(filename)

    def extract_strings_from_file(self, filename):
        with open(filename) as f:
            text = f.read()
        
        found_strings = re.findall('"([^"]*)"', text)
        self.strings = self.strings + found_strings

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} [RUST_SOURCE_DIR]")
        exit(1)
    
    rust_string_extractor = RustStringExtractor()
    rust_string_extractor.extract_strings_from_files(sys.argv[1])

    for string in rust_string_extractor.strings:
        print(string)

