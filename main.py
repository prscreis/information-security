from cryptography.hazmat.primitives import serialization
from Hashing import verify_file_integrity
from KeyGeneration import generate_rsa_key_pair, encrypt_file, decrypt_file, generate_file_hash

# save_key_to_file
def save_key_to_file(key, file_path):
    with open(file_path, "wb") as f:
        f.write(key)

# load_key_from_file
def load_key_from_file(file_path):
    with open(file_path, "rb") as f:
        key = f.read()
    return key


def main():
    print("Secure File Transfer System")

    # Generate key pair
    private_key, public_key = generate_rsa_key_pair()

    # Save public key to a file
    save_key_to_file(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        "files/public_key.pem"
    )

    # Encrypt file using public key
    encrypted_data = encrypt_file("files/file.txt", public_key)
    with open("files/encrypted_file.bin", "wb") as f:
        f.write(encrypted_data)

    # Decrypt file using private key
    encrypted_data = load_key_from_file("files/encrypted_file.bin")
    decrypted_data = decrypt_file(encrypted_data, private_key)
    with open("files/decrypted_file.txt", "wb") as f:
        f.write(decrypted_data)

    # Generate hash of original file
    original_hash = generate_file_hash("files/file.txt")

    # Verify integrity of received file
    is_integrity_verified = verify_file_integrity(original_hash, "files/decrypted_file.txt")
    if is_integrity_verified:
        print("Integrity OK!")
    else:
        print("Integrity Verification Failed!")

if __name__ == "__main__":
    main()