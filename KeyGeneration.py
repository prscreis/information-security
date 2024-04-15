import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_rsa_key_pair()

        
# encrypt_file
def encrypt_file(file_path, public_key):
    with open(file_path, "rb") as f:
        data = f.read()
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

#  decrypt_file
def decrypt_file(encrypted_data, private_key):
    plaintext = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# generate_file_hash
def generate_file_hash(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    hash_value = hashlib.sha256(data).digest()
    return hash_value


print("Private Key:")
print(private_key.private_numbers())

print("Public Key:")
print(public_key.public_numbers())