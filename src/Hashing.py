import hashlib

from File import load_file, save_file

def generate_file_hash(file_path, algorithm=hashlib.sha256):
    data = load_file(file_path)
    return algorithm(data).digest()


def verify_file_integrity(original_file_hash, file_path, algorithm=hashlib.sha256):
    file_hash = generate_file_hash(file_path, algorithm)
    
    return file_hash == original_file_hash


def save_file_hash_to_file(file_path, hash_file_path, algorithm=hashlib.sha256):
    save_file(generate_file_hash(file_path, algorithm), hash_file_path)
    
    
# test
# if __name__ == '__main__':
#     save_file_hash_to_file('./files/test.txt', './files/test_hash.txt')
    
#     file_hash = load_file('./files/test_hash.txt')
#     print(verify_file_integrity(file_hash, './files/test.txt'))