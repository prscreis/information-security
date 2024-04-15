from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# test
if __name__ == '__main__':
    private_key, public_key = generate_rsa_key_pair()

    print("Private Key:")
    print(private_key.private_numbers())

    print("Public Key:")
    print(public_key.public_numbers())