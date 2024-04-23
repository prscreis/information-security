import os

from Encryption import decrypt_file, encrypt_file
from File import load_file, save_file
from KeyManagement import generate_rsa_key_pair


def test_encrypt():
    private_key, public_key = generate_rsa_key_pair()
    
    file_content = load_file('tests/files/test_encrypt.txt')
    encrypted_content = encrypt_file('tests/files/test_encrypt.txt', public_key)
    save_file(encrypted_content, 'tests/files/encrypted_test_encrypt.bin')
    
    decrypted_content = decrypt_file('tests/files/encrypted_test_encrypt.bin', private_key)
    
    assert file_content == decrypted_content
    
    os.remove('tests/files/encrypted_test_encrypt.bin')