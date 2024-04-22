import hashlib

from File import load_file

def generate_file_hash(file_path, algorithm=hashlib.sha256):
    data = load_file(file_path)
    return algorithm(data).digest()


def verify_file_integrity(original_file_hash, file_path, algorithm=hashlib.sha256):
    file_hash = generate_file_hash(file_path, algorithm)
    
    return file_hash == original_file_hash