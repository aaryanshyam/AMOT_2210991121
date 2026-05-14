import os
import random
import struct

def generate_safe_signature_mock(filename="wannacry_payload.wncry"):
    """
    Generates a 100% SAFE binary that mimics the STATICAL signature of WannaCry.
    It contains NO executable code, only random high-entropy data and a 
    legit-looking PE structure to test the 99% accuracy of our ML Ensemble.
    """
    print(f"[*] Assembling Safe Research Mock: {filename}")
    
    # 1. PE Header (Simplified structure for static analysis parsing)
    # This is a dummy valid PE header that pefile and our analyzer will recognize
    pe_header = (
        b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00" + # DOS Header
        b"\x00" * 64 + 
        b"PE\x00\x00" + # PE Signature
        b"\x4c\x01" +   # Machine: Intel 386
        b"\x08\x00" +   # Number of Sections: 8 (High, suspicious)
        b"\x00\x00\x00\x00\x00\x00\x00\x00" + 
        b"\xe0\x00" +   # Size of Optional Header
        b"\x02\x01"     # Characteristics
    )
    
    # 2. Add High Entropy "Payload" (Random data)
    # This mimics encrypted ransomware payloads to trigger entropy sensors
    payload = os.urandom(1024 * 50) # 50KB of random data
    
    # 3. Add strings that look like suspicious API imports
    # Our analyzer looks for these in the binary data/imports
    api_markers = [
        b"CryptEncrypt", b"CryptGenKey", b"CryptAcquireContext",
        b"CreateServiceA", b"StartServiceA", b"RegSetValueExA",
        b"TerminateProcess", b"OpenProcess", b"InternetOpenA",
        b"WNetOpenEnumA", b"ControlService", b"ShellExecuteA"
    ]
    
    with open(filename, "wb") as f:
        f.write(pe_header)
        f.write(b"\x00" * 100) # Padding
        for api in api_markers:
            f.write(api + b"\x00")
        f.write(payload)

    print(f"[+] Success! Mock created at: {os.path.abspath(filename)}")
    print("[!] THIS FILE IS SAFE. It contains no machine code, only random data and strings.")
    print("[!] It will trigger a 'Malicious' verdict because of its signature.")

if __name__ == "__main__":
    generate_safe_signature_mock()
