from KeyGeneration import generate_rsa_key_pair, save_key_to_file, encrypt_file, load_key_from_file, decrypt_file, generate_file_hash

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
        "public_key.pem"
    )

    # Encrypt file using public key
    encrypted_data = encrypt_file("file.txt", public_key)
    with open("encrypted_file.bin", "wb") as f:
        f.write(encrypted_data)

    # Decrypt file using private key
    encrypted_data = load_key_from_file("encrypted_file.bin")
    decrypted_data = decrypt_file(encrypted_data, private_key)
    with open("decrypted_file.txt", "wb") as f:
        f.write(decrypted_data)

    # Generate hash of original file
    original_hash = generate_file_hash("file.txt")

    # Verify integrity of received file
    is_integrity_verified = verify_integrity(original_hash, "decrypted_file.txt")
    if is_integrity_verified:
        print("Integrity OK!")
    else:
        print("Integrity Verification Failed!")

if __name__ == "__main__":
    main()