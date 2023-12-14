import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES

def passphrase_to_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=b"salt",
        iterations=100000
    ) 
    return kdf.derive(passphrase.encode())


def encrypt(data: bytes, passphrase: str) -> tuple[bytes, bytes]:
    data = data
    key = passphrase_to_key(passphrase)
    # Create cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))

    # Save the IV and the ciphertext
    iv = cipher.iv
    ciphertext = ct_bytes
    return iv, ciphertext

def decrypt(iv: bytes, ciphertext: bytes, passphrase: str) -> str:
    key = passphrase_to_key(passphrase)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size).decode()

def encrypt_file(in_filename, out_filename, passphrase):
    with open(in_filename, 'rb') as f:
        data = f.read()

    iv, ciphertext = encrypt(data, passphrase)

    with open(out_filename, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)

def decrypt_file(in_filename: str, out_filename: str, passphrase: str):
    with open(in_filename, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    
    plaintext = decrypt(iv, ciphertext, passphrase)

    with open(out_filename, 'wb') as f:
        f.write(plaintext.encode())


def cryptfast(config: dict, passphrase: str):
    encrypt_file(config["original_file_name"], config["encrypted_file_name"], passphrase)
    if os.path.exists(config["encrypted_file_name"]):
        os.remove(config["original_file_name"])
    else:
        raise Exception("Something went wrong, encryption file not found: %s" % config["out_filename"])

def decryptfast(config: dict, passphrase: str):
    decrypt_file(config["encrypted_file_name"], config["original_file_name"], passphrase)
    if os.path.exists(config["original_file_name"]):
        os.remove(config["encrypted_file_name"])
    else:
        raise Exception("Something went wrong, decryption file not found: %s" % config["original_file_name"])