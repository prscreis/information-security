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
    # Generate key pair
    private_key, public_key = generate_rsa_key_pair()

    # Save public key to a file
    save_public_key_file(public_key, public_key_path)
    
    # Save private key to a file
    save_private_key_file(private_key, private_key_path)
    

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.argument('encrypted_file_path', type=click.Path())
@click.argument('public_key_path', type=click.Path(exists=True))
def encrypt(file_path, encrypted_file_path, public_key_path):
    # Encrypt file using public key
    public_key = load_public_key_file(public_key_path)
    encrypted_data = encrypt_file(file_path, public_key)
    save_file(encrypted_data, encrypted_file_path)
    
    
@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.argument('decrypted_file_path', type=click.Path())
@click.argument('private_key_path', type=click.Path(exists=True))
def decrypt(file_path, decrypted_file_path, private_key_path):
    # Decrypt file using private key
    private_key = load_private_key_file(private_key_path)
    decrypted_data = decrypt_file(file_path, private_key)
    save_file(decrypted_data, decrypted_file_path)
    
    
@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--hash-file-path', '-hfp', default=None, help='Path to the hash file (optional). If not specified, the generated hash is printed on the console (in hexadecimal)')
def hash(file_path, hash_file_path):
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
    original_hash = load_file(hash_file_path)
    
    if verify_file_integrity(original_hash, file_path):
        click.echo("Integrity check passed!")
    else:
        click.echo("Integrity check failed!")
    

if __name__ == "__main__":
    cli()