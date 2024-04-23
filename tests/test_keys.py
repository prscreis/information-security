import os

from KeyManagement import generate_rsa_key_pair, load_private_key_file, load_public_key_file, save_private_key_file, save_public_key_file

def test_keys():
    private_key, public_key = generate_rsa_key_pair()
    
    # comparison using _numbers() methods, as per described here: https://github.com/pyca/cryptography/issues/2122#issuecomment-120570866
    assert private_key.public_key().public_numbers() == public_key.public_numbers()
    
    # another keys pair won't match with the previous generated pair
    another_private_key, another_public_key = generate_rsa_key_pair()
    assert another_private_key.public_key().public_numbers() != public_key.public_numbers()
    assert private_key.public_key().public_numbers() != another_public_key.public_numbers()
    
    
def test_public_key():
    _, public_key = generate_rsa_key_pair()
    
    save_public_key_file(public_key, 'tests/files/pbk.pem')
    loaded_public_key = load_public_key_file('tests/files/pbk.pem')
    
    # generated and loaded from file keys should match
    assert public_key.public_numbers() == loaded_public_key.public_numbers()
    
    os.remove('tests/files/pbk.pem')
    
    
def test_private_key():
    private_key, _ = generate_rsa_key_pair()
    
    save_private_key_file(private_key, 'tests/files/pvk.pem')
    loaded_private_key = load_private_key_file('tests/files/pvk.pem')
    
    # generated and loaded from file keys should match
    assert private_key.private_numbers() == loaded_private_key.private_numbers()
    
    os.remove('tests/files/pvk.pem')
