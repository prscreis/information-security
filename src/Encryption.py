import pickle
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as as_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from File import load_file
from KeyManagement import generate_key_bundle

        
def rsa_encrypt(data, public_key):   
    encrypted_data = public_key.encrypt(
        data,
        as_padding.OAEP(
            mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data
    
    
def rsa_decrypt(data, private_key):
    try:
        decrypted_data = private_key.decrypt(
            data,
            as_padding.OAEP(
                mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except :
        return None
    return decrypted_data


def encrypt_file(file_path, public_key):    
    file_content = load_file(file_path)
    key_bundle = generate_key_bundle()
    
    # create cipher/encryptor
    encryptor = Cipher(algorithms.AES(key_bundle['key']), modes.CBC(key_bundle['iv'])).encryptor()
    
    # encrypt content
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    content_to_encrypt = padder.update(file_content) + padder.finalize()
    encrypted_file_content = encryptor.update(content_to_encrypt) + encryptor.finalize()
    
    # encrypt key bundle
    encrypted_key_bundle = rsa_encrypt(pickle.dumps(key_bundle), public_key)
    
    # return content and bundle
    return encrypted_file_content, encrypted_key_bundle


def decrypt_file(encrypted_file_path, private_key, key_bundle_path):
    file_content = load_file(encrypted_file_path)
    key_bundle = load_file(key_bundle_path)
    
    # decrypt key bundle
    decrypted_key_bundle = pickle.loads(rsa_decrypt(key_bundle, private_key))
    
    # create cipher/decryptor
    decryptor = Cipher(algorithms.AES(decrypted_key_bundle['key']), modes.CBC(decrypted_key_bundle['iv'])).decryptor()
    
    # decrypt content
    decrypted_to_unpad = decryptor.update(file_content) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_file_content = unpadder.update(decrypted_to_unpad) + unpadder.finalize()
    
    # return content
    return decrypted_file_content
