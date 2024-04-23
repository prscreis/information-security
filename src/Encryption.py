from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from File import load_file

        
def encrypt(data, public_key):   
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data
    
    
def decrypt(data, private_key):
    try:
        decrypted_data = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except :
        return None
    return decrypted_data


def encrypt_file(file_path, public_key):
    data = load_file(file_path)
    return encrypt(data, public_key)


def decrypt_file(encrypted_file_path, private_key):
    data = load_file(encrypted_file_path)        
    return decrypt(data, private_key)


# test
# if __name__ == '__main__':
#     private_key, public_key = generate_rsa_key_pair()

#     encrypted_data = encrypt_file('test.txt', public_key)
#     print(encrypted_data)
    
#     decrypted_data = decrypt(encrypted_data, private_key)
#     print('----------------------------')
#     print(decrypted_data)