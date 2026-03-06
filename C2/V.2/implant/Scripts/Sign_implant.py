import os
import subprocess
import datetime

# Configuration
TARGET_EXE = r"implant.exe"
CERT_NAME = "EreboxCorp"
PFX_FILE = "erebos_cert.pfx"
PFX_PASS = "rzdhop_is_a_nice_guy"

def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        print(f"[-] Error: {result.stderr}")
    return result.stdout

def generate_and_sign():
    print(f"[*] Generating CA for: {CERT_NAME}")
    
    # 1. Create Private Key & Self-Signed Cert (OpenSSL)
    openssl_cmd = (
        f'openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem '
        f'-days 365 -nodes -subj "/CN={CERT_NAME}/O=ResearchOrg/C=FR" '
        f'-addext "extendedKeyUsage = codeSigning"'
    )
    run_cmd(openssl_cmd)

    # 2. Export to PFX (PKCS#12)
    pfx_cmd = (
        f'openssl pkcs12 -export -out {PFX_FILE} -inkey key.pem '
        f'-in cert.pem -password pass:{PFX_PASS}'
    )
    run_cmd(pfx_cmd)

    # 3. Sign the Binary using Signtool
    print(f"[*] Signing binary: {TARGET_EXE}")
    sign_cmd = (
        f'signtool sign /f {PFX_FILE} /p {PFX_PASS} '
        f'/fd SHA256 /v "{TARGET_EXE}"'
    )
    output = run_cmd(sign_cmd)

    os.remove("key.pem")
    os.remove("cert.pem")

if __name__ == "__main__":
    generate_and_sign()