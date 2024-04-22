from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from File import load_file

        
def encrypt(data, public_key, algorithm=hashes.SHA256):
    algorithm_obj = algorithm() if algorithm != hashes.BLAKE2b else algorithm(64)
    
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=algorithm_obj),
            algorithm=algorithm_obj,
            label=None
        )
    )
    return encrypted_data
    
    
def decrypt(data, private_key, algorithm=hashes.SHA256):
    algorithm_obj = algorithm() if algorithm != hashes.BLAKE2b else algorithm(64)
    
    try:
        decrypted_data = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=algorithm_obj),
                algorithm=algorithm_obj,
                label=None
            )
        )
    except :
        return None
    return decrypted_data


def encrypt_file(file_path, public_key, algorithm=hashes.SHA256):
    data = load_file(file_path)
    return encrypt(data, public_key, algorithm)


def decrypt_file(encrypted_file_path, private_key, algorithm=hashes.SHA256):
    data = load_file(encrypted_file_path)        
    return decrypt(data, private_key, algorithm)


# test
# if __name__ == '__main__':
#     private_key, public_key = generate_rsa_key_pair()

#     encrypted_data = encrypt_file('test.txt', public_key)
#     print(encrypted_data)
    
#     decrypted_data = decrypt(encrypted_data, private_key)
#     print('----------------------------')
#     print(decrypted_data)