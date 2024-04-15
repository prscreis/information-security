import hashlib

def generate_file_hash(file_path, algorithm=hashlib.sha256):
    with open(file_path, 'rb') as f:
        data = f.read()
    return algorithm(data).digest()


def verify_file_integrity(original_file_hash, file_path):
    original_hash = original_file_hash
    file_hash = generate_file_hash(file_path)
    
    if file_hash == original_hash:
        return True
    else:
        return False