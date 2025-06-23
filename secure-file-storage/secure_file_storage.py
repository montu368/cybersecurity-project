import json
import time
import hashlib
import os
from cryptography.fernet import Fernet


# Generate a new encryption key
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to 'key.key'")


# Load an existing encryption key
def load_key():
    if not os.path.exists("key.key"):
        raise FileNotFoundError("Encryption key not found. Please generate a new key.")
    with open("key.key", "rb") as key_file:
        return key_file.read()


# Encrypt a file and save metadata
def encrypt_file(file_path):
    key = load_key()
    fernet = Fernet(key)

    # Read the file's content
    with open(file_path, "rb") as file:
        original_data = file.read()

    # Encrypt the content
    encrypted_data = fernet.encrypt(original_data)

    # Save the encrypted file
    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    # Generate metadata
    metadata = {
        "original_name": file_path,
        "encrypted_name": encrypted_file_path,
        "timestamp": time.ctime(),
        "hash": hashlib.sha256(original_data).hexdigest(),
    }

    # Save metadata to a JSON file
    metadata_file_path = f"{file_path}.meta.json"
    with open(metadata_file_path, "w") as metadata_file:
        json.dump(metadata, metadata_file, indent=4)

    print(f"File encrypted and saved as '{encrypted_file_path}'")
    print(f"Metadata saved as '{metadata_file_path}'")


# Decrypt a file and verify integrity
def decrypt_file(file_path):
    if not file_path.endswith(".enc"):
        print("Error: File does not have the '.enc' extension.")
        return

    key = load_key()
    fernet = Fernet(key)

    # Read encrypted data
    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Load metadata
    metadata_file_path = file_path.replace(".enc", ".meta.json")
    if not os.path.exists(metadata_file_path):
        print(f"Error: Metadata file '{metadata_file_path}' not found.")
        return

    with open(metadata_file_path, "r") as metadata_file:
        metadata = json.load(metadata_file)

    # Decrypt the data
    decrypted_data = fernet.decrypt(encrypted_data)

    # Verify hash
    decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
    if decrypted_hash != metadata["hash"]:
        print("Warning: Hash mismatch! The file may have been tampered with.")
        return

    # Save the decrypted file
    original_file_path = metadata["original_name"]
    with open(original_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"File decrypted and saved as '{original_file_path}'")


# Generate a SHA-256 hash of a file
def hash_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            sha256.update(chunk)
    hash_value = sha256.hexdigest()
    print(f"SHA-256 Hash: {hash_value}")
    return hash_value


# Main menu
def main():
    print("Secure File Storage System")
    print("1. Generate Encryption Key")
    print("2. Encrypt a File")
    print("3. Decrypt a File")
    print("4. Hash a File")
    print("5. Exit")

    choice = input("Enter your choice: ").strip()

    if choice == "1":
        generate_key()
    elif choice == "2":
        file_path = input("Enter the file path to encrypt: ").strip()
        encrypt_file(file_path)
    elif choice == "3":
        file_path = input("Enter the file path to decrypt: ").strip()
        decrypt_file(file_path)
    elif choice == "4":
        file_path = input("Enter the file path to hash: ").strip()
        hash_file(file_path)
    elif choice == "5":
        print("Exiting...")
        exit()
    else:
        print("Invalid choice. Please try again.")


if __name__ == "__main__":
    while True:
        main()
