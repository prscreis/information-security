from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

def encrypt_file(file_path, public_key):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

private_key, public_key = rsa.generate_rsa_key_pair()
encrypted_data = encrypt_file('test.txt', public_key)
print(encrypted_data)