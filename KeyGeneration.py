from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashlib

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_rsa_key_pair()

# save_key_to_file
def save_key_to_file(key, file_path):
    with open(file_path, "wb") as f:
        f.write(key)
        
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

# load_key_from_file
def load_key_from_file(file_path):
    with open(file_path, "rb") as f:
        key = f.read()
    return key

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