from KeyManagement import generate_rsa_key_pair

def test_keys():
    private_key, public_key = generate_rsa_key_pair()
    assert private_key.public_key() == public_key
    
    # another keys pair won't match with the previous generated pair
    another_private_key, another_public_key = generate_rsa_key_pair()
    assert another_private_key.public_key() != public_key
    assert private_key.public_key() != another_public_key
    
    print("Hello")
    print(private_key.private_numbers())
    
    