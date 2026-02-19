from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

"""
Activity: Digital Signature System
Objective: Understand public-key cryptography, key generation, signing, and verification.
Requirements: RSA, SHA-256 hashing.
"""

# ---------------------------------------------------------
# 1. KEY GENERATION
# ---------------------------------------------------------
def generate_keys():
    """
    Generates an RSA private and public key pair.
    RSA is an asymmetric algorithm used for digital signatures.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# ---------------------------------------------------------
# 2. SIGN MESSAGE (Using Private Key & SHA-256)
# ---------------------------------------------------------
def sign_message(private_key, message):
    """
    Signs a message using the sender's private key.
    Hashing: SHA-256 is used to create a message digest before signing.
    Padding: PSS (Probabilistic Signature Scheme) is recommended for RSA.
    """
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# ---------------------------------------------------------
# 3. VERIFY SIGNATURE (Using Public Key & SHA-256)
# ---------------------------------------------------------
def verify_signature(public_key, message, signature):
    """
    Verifies the signature using the sender's public key.
    If the content or signature was tampered with, verification fails.
    """
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------------------------------------------------------
# MAIN PROGRAM LOGIC
# ---------------------------------------------------------
def main():
    print("="*40)
    print("     DIGITAL SIGNATURE SYSTEM (RSA)(Herry(20230905090031))")
    print("="*40)

    # User Input
    message = input("\n[>] Enter the plan/message to sign: ")

    # Step 1: Generate Keys
    print("\n[*] Generating RSA 2048-bit key pair...")
    private_key, public_key = generate_keys()
    print("[+] Key pair generated successfully.")

    # Step 2: Sign Message
    print("[*] Hashing message with SHA-256 and signing with Private Key...")
    signature = sign_message(private_key, message)
    print(f"[+] Digital Signature created (Length: {len(signature)} bytes)")

    # Step 3: Verify Signature
    print("\n[*] Verifying signature with Public Key...")
    is_valid = verify_signature(public_key, message, signature)

    if is_valid:
        print("\n" + "="*40)
        print(" VERIFICATION RESULT: SUCCESSFUL ✅")
        print(" Integrity: The message has not been altered.")
        print(" Authenticity: Verified by Private Key owner.")
        print("="*40)
    else:
        print("\n" + "="*40)
        print(" VERIFICATION RESULT: FAILED ❌")
        print(" Warning: Possible tampering or invalid key.")
        print("="*40)

if __name__ == "__main__":
    main()
