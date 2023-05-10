import idautils

def detect_rust() -> bool:
    strings = idautils.Strings()

    for s in strings:
        if "/rustc/" in str(s):
            return True
    
    return False

if __name__ == "__main__":
    print(detect_rust())

