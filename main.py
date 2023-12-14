from encryptor import encrypt, decrypt, encrypt_file, decrypt_file, cryptfast, decryptfast

def main():
    # Your main code logic here
    encrypted = encrypt(b"test", "key")
    decrypted = decrypt(encrypted[0], encrypted[1], "key")
    print(encrypted)
    print(decrypted)
    
    config = {
        "original_file_name": "test.txt",
        "encrypted_file_name": "encrypted",
    }
    
    decryptfast(config, "key")
    # encrypt_file("test.txt", "encrypted.txt", "key")
    # decrypt_file("encrypted", "decrypted.txt", "key")

if __name__ == "__main__":
    main()