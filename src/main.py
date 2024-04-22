from cryptography.hazmat.primitives import serialization
from File import load_file, save_file
from Hashing import verify_file_integrity, generate_file_hash
from KeyManagement import generate_rsa_key_pair, load_private_key_file, load_public_key_file, save_private_key_file, save_public_key_file
from Encryption import encrypt_file, decrypt



def main():
    print("Secure File Transfer System")

    # # Generate key pair
    # private_key, public_key = generate_rsa_key_pair()

    # # Save public key to a file
    # save_public_key_file(public_key, "files/public_key.pem")
    
    # # Save private key to a file
    # save_private_key_file(private_key, 'files/private_key.pem')
    
    # Load keys from file
    public_key = load_public_key_file("files/public_key.pem")
    private_key = load_private_key_file('files/private_key.pem')
    

    # Encrypt file using public key
    encrypted_data = encrypt_file("files/file.txt", public_key)
    save_file(encrypted_data, "files/encrypted_file.bin")

    # Decrypt file using private key
    decrypted_data = decrypt(encrypted_data, private_key)
    save_file(decrypted_data, "files/decrypted_file.txt")

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