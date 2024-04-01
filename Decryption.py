from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_file(encrypted_file, private_key):
    try:
        decrypted_data = private_key.decrypt(
            encrypted_file,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except :
        return None
    return decrypted_data