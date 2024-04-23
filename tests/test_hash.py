import os
from File import load_file
from Hashing import generate_file_hash, save_file_hash_to_file, verify_file_integrity


def test_hash_generation():
    file_hash_hex = generate_file_hash('tests/files/test_hash.txt', True)
    file_hash_binary = generate_file_hash('tests/files/test_hash.txt')
    
    assert len(file_hash_binary) == 32 # 32 bytes
    assert len(file_hash_hex) == 64 # 32 bytes
    
    assert file_hash_hex == '349fac920d306b2c3efdff322010dda443c483a712f8816a37270e68c5206e14'
    
    # hex and bytes versions should match
    assert file_hash_binary == bytes.fromhex(file_hash_hex)
    
    
def test_hash_storing():
    save_file_hash_to_file('tests/files/test_hash.txt', 'tests/files/hash_file.bin')
    file_content = load_file('tests/files/hash_file.bin')
    
    # content returned by generate_file_hash and saved by 
    # save_file_hash_to_file should match
    assert file_content == generate_file_hash('tests/files/test_hash.txt')
    
    os.remove('tests/files/hash_file.bin')
    
    
def test_integrity_check():
    file_hash = generate_file_hash('tests/files/test_hash.txt')
    
    # verification should succeed when using file just generated hash
    assert verify_file_integrity(file_hash, 'tests/files/test_hash.txt')
    
    # verification should not succed for a different version of the original file
    assert not verify_file_integrity(file_hash, 'tests/files/test_hash_altered.txt')