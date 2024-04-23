from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from File import load_file, save_file

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    return private_key, public_key


def save_public_key_file(public_key, file_path):
    save_file(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        file_path
    )
    
    
def save_private_key_file(private_key, file_path):
    save_file(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ),
        file_path
    )


def load_public_key_file(file_path):
    public_key = serialization.load_pem_public_key(
        load_file(file_path)
    )
    
    return public_key
    
    
def load_private_key_file(file_path):
    private_key = serialization.load_pem_private_key(
        load_file(file_path),
        password=None
    )
    
    return private_key
