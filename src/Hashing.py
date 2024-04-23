import hashlib

from File import load_file, save_file

def generate_file_hash(file_path, digest_hexadecimal=False, algorithm=hashlib.sha256):
    data = load_file(file_path)
    return algorithm(data).digest() if not digest_hexadecimal else algorithm(data).hexdigest()


def verify_file_integrity(original_file_hash, file_path, algorithm=hashlib.sha256):
    file_hash = generate_file_hash(file_path, False, algorithm)
    return file_hash == original_file_hash


def save_file_hash_to_file(file_path, hash_file_path, algorithm=hashlib.sha256):
    save_file(generate_file_hash(file_path, False, algorithm), hash_file_path)
