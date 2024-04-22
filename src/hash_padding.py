import hashlib
from enum import Enum
# Implement here the hash method
class HashMethod(Enum):
    MD5 = 1
    SHA256 = 2
    SHA512 = 3
# Implement here the padding method
class Padding(Enum):
    PKCS7 = 1
    ZERO = 2
# Implement the function that takes in a data and a hash method and returns the hashed data
def hash_data(data, hash_method=HashMethod.MD5, padding=Padding.PKCS7):
    if hash_method == HashMethod.MD5:
        hash_object = hashlib.md5()
    elif hash_method == HashMethod.SHA256:
        hash_object = hashlib.sha256()
    elif hash_method == HashMethod.SHA512:
        hash_object = hashlib.sha512()
    else:
        raise ValueError("Invalid hash method")

    if padding == Padding.PKCS7:
        # Implement PKCS7 padding
        padded_data = data + bytes([16 - len(data) % 16] * (16 - len(data) % 16))
    elif padding == Padding.ZERO:
        # Implement zero padding
        padded_data = data + bytes([0] * (16 - len(data) % 16))
    else:
        raise ValueError("Invalid padding method")
    # Update the hash object with the padded data
    hash_object.update(padded_data)
    return hash_object.hexdigest()

# Example usage
data = b"Hello, World!"
hashed_data = hash_data(data, hash_method=HashMethod.SHA256, padding=Padding.PKCS7)
print(hashed_data)
