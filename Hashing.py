import hashlib

def generate_file_hash(file_path, algorithm=hashlib.sha256):
    with open(file_path, 'rb') as f:
        data = f.read()
    return algorithm(data).digest()