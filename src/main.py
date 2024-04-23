import click

from File import load_file, save_file
from Hashing import verify_file_integrity, generate_file_hash
from KeyManagement import generate_rsa_key_pair, load_private_key_file, load_public_key_file, save_private_key_file, save_public_key_file
from Encryption import decrypt_file, encrypt_file


@click.group()
def cli():
    pass

@cli.command()
@click.argument('public_key_path', type=click.Path())
@click.argument('private_key_path', type=click.Path())
def keypair(public_key_path, private_key_path):
    """ 
    Generate RSA key pair.
    
    PUBLIC_KEY_PATH is the path to save the generated public key.
    PRIVATE_KEY_PATH is the path to save the generated private key.
    """
    private_key, public_key = generate_rsa_key_pair()

    save_public_key_file(public_key, public_key_path)
    save_private_key_file(private_key, private_key_path)
    

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.argument('public_key_path', type=click.Path(exists=True))
@click.argument('key_bundle_path', type=click.Path())
@click.argument('encrypted_file_path', type=click.Path())
def encrypt(file_path, public_key_path, encrypted_file_path, key_bundle_path):
    """ 
    Encrypt file using RSA public key.
    
    FILE_PATH is the path to the file to be encrypted.
    PUBLIC_KEY_PATH is the path to the public key to be used to encrypt the file.
    KEY_BUNDLE_PATH is the path to save the key bundle (used to decrypt the file).
    ENCRYPTED_FILE_PATH is the path to save the encrypted file.
    """
    public_key = load_public_key_file(public_key_path)
    encrypted_data, key_bundle = encrypt_file(file_path, public_key)
    save_file(encrypted_data, encrypted_file_path)
    save_file(key_bundle, key_bundle_path)
    
    
@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.argument('key_bundle_path', type=click.Path(exists=True))
@click.argument('private_key_path', type=click.Path(exists=True))
@click.argument('decrypted_file_path', type=click.Path())
def decrypt(file_path, key_bundle_path, private_key_path, decrypted_file_path):
    """ 
    Decrypt file using RSA private key.
    
    FILE_PATH is the path to the file to be decrypted.
    KEY_BUNDLE_PATH is the path to the key bundle to be used to decrypt the file.
    PRIVATE_KEY_PATH is the path to the private key to be used to decrypt the file.
    DECRYPTED_FILE_PATH is the path to save the decrypted file.
    """
    private_key = load_private_key_file(private_key_path)
    decrypted_data = decrypt_file(file_path, private_key, key_bundle_path)
    save_file(decrypted_data, decrypted_file_path)
    
    
@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--hash-file-path', '-hfp', default=None, help='Path to the hash file (optional). If not specified, the generated hash is printed on the console (in hexadecimal)')
def hash(file_path, hash_file_path):
    """ 
    Generate hash digest of file.
    
    FILE_PATH is the path to the file to have its hash digest generated.
    """
    if(hash_file_path == None):
        hex_original_hash = generate_file_hash(file_path, True)
        click.echo(f"Generated hash:\n{hex_original_hash}")
    else:
        original_hash = generate_file_hash(file_path)
        save_file(original_hash, hash_file_path)
    
    
@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.argument('hash_file_path', type=click.Path(exists=True))
def verify(file_path, hash_file_path):
    """ 
    Verify whether a hash digest corresponds to file content.
    
    FILE_PATH is the path to the file to have its hash digest verified.
    HASH_FILE_PATH is the path to the hash file associated to the file to be verified.
    
    """
    original_hash = load_file(hash_file_path)
    
    if verify_file_integrity(original_hash, file_path):
        click.echo("Integrity check passed!")
    else:
        click.echo("Integrity check failed!")
    

if __name__ == "__main__":
    cli()