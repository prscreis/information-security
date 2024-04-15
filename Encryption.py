from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from KeyGeneration import generate_rsa_key_pair

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

# test
if __name__ == '__main__':
    private_key, public_key = generate_rsa_key_pair()

    encrypted_data = encrypt_file('test.txt', public_key)
    print(encrypted_data)
    
    decrypted_data = decrypt_file(encrypted_data, private_key)
    print('----------------------------')
    print(decrypted_data)