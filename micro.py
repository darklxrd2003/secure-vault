import os
import shutil
import getpass
import json
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class Vault:
    def __init__(self, name, password):
        self.name = name
        self.key = self.generate_key(password)
        self.path = os.path.join(os.getcwd(), name)
        if not os.path.exists(self.path):
            os.makedirs(self.path)

    def generate_key(self, password):
        salt = b'\x00' * 16  # In a real application, use a unique salt for each user
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def get_fernet(self):
        return Fernet(self.key)

    def encrypt_folder(self, folder_path):
        # Move the folder into the vault directory
        folder_name = os.path.basename(folder_path)
        original_location = os.path.abspath(folder_path)  # Store original location
        new_folder_path = os.path.join(self.path, folder_name)
        shutil.move(folder_path, new_folder_path)
        
        # Encrypt files within the moved folder
        fernet = self.get_fernet()
        for root, dirs, files in os.walk(new_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted_data = fernet.encrypt(data)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
        print(f"Folder '{folder_path}' moved to vault and encrypted.")
        
        # Store original location in a file within the vault
        with open(os.path.join(self.path, '_original_location.txt'), 'w') as f:
            f.write(original_location)

    def decrypt_folder(self):
        # Retrieve original location from the stored file
        with open(os.path.join(self.path, '_original_location.txt'), 'r') as f:
            original_location = f.read().strip()
        
        # Decrypt files within the vault folder
        fernet = self.get_fernet()
        for root, dirs, files in os.walk(self.path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                try:
                    data = fernet.decrypt(encrypted_data)
                except:
                    continue
                with open(file_path, 'wb') as f:
                    f.write(data)
        
        # Move the decrypted folder contents back to the original location
        decrypted_folder_path = os.path.join(self.path, os.listdir(self.path)[0])  # Assume there's only one folder in the vault
        shutil.move(decrypted_folder_path, original_location)
        print(f"Folder decrypted and moved back to '{original_location}'.")

class SecurityVaultSystem:
    def __init__(self):
        self.vaults = {}
        self.load_vaults()

    def load_vaults(self):
        if os.path.exists('vaults.json'):
            with open('vaults.json', 'r') as f:
                self.vaults = json.load(f)
                print("Loaded vaults:", self.vaults)  # Debugging statement

    def save_vaults(self):
        with open('vaults.json', 'w') as f:
            json.dump(self.vaults, f)
        print("Saved vaults:", self.vaults)  # Debugging statement

    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def create_vault(self, name, password):
        if name in self.vaults:
            print("Vault already exists.")
            return
        salt = os.urandom(16)
        key = self.generate_key(password, salt)
        self.vaults[name] = {
            'password_hash': hashlib.sha256(password.encode()).hexdigest(),
            'salt': base64.b64encode(salt).decode()
        }
        os.makedirs(name)
        print(f"Vault '{name}' created.")
        self.save_vaults()

    def delete_vault(self, name):
        if name not in self.vaults:
            print("Vault does not exist.")
            return
        shutil.rmtree(name)
        del self.vaults[name]
        print(f"Vault '{name}' deleted.")
        self.save_vaults()

    def change_vault_password(self, name, old_password, new_password):
        if name not in self.vaults:
            print("Vault does not exist.")
            return
        vault_info = self.vaults[name]
        if vault_info['password_hash'] != hashlib.sha256(old_password.encode()).hexdigest():
            print("Incorrect password.")
            return
        salt = base64.b64decode(vault_info['salt'])
        new_key = self.generate_key(new_password, salt)
        self.vaults[name]['password_hash'] = hashlib.sha256(new_password.encode()).hexdigest()
        print(f"Password for vault '{name}' changed.")
        self.save_vaults()

    def access_vault(self, name, password):
        if name not in self.vaults:
            print("Vault does not exist.")
            return
        vault_info = self.vaults[name]
        print("Vault info:", vault_info)  # Debugging statement
        if vault_info['password_hash'] != hashlib.sha256(password.encode()).hexdigest():
            print("Incorrect password.")
            return
        salt = base64.b64decode(vault_info['salt'])
        return Vault(name, password)

    def menu(self):
        print("\nWelcome to the Security Vault System")
        while True:
            print("\n1. Create Vault\n2. Delete Vault\n3. Change Vault Password\n4. Access Vault\n5. Exit")
            choice = input("Choose an option: ")
            if choice == '1':
                name = input("Enter vault name: ")
                password = getpass.getpass("Enter vault password: ")
                self.create_vault(name, password)
            elif choice == '2':
                name = input("Enter vault name: ")
                self.delete_vault(name)
            elif choice == '3':
                name = input("Enter vault name: ")
                old_password = getpass.getpass("Enter current vault password: ")
                new_password = getpass.getpass("Enter new vault password: ")
                self.change_vault_password(name, old_password, new_password)
            elif choice == '4':
                name = input("Enter vault name: ")
                password = getpass.getpass("Enter vault password: ")
                vault = self.access_vault(name, password)
                if vault:
                    self.vault_menu(vault)
            elif choice == '5':
                print("Exiting.")
                break
            else:
                print("Invalid choice, please try again.")

    def vault_menu(self, vault):
        while True:
            print(f"\nVault '{vault.name}' Menu")
            print("1. Encrypt Folder\n2. Decrypt Folder\n3. Back")
            choice = input("Choose an option: ")
            if choice == '1':
                folder_path = input("Enter folder path to encrypt: ")
                vault.encrypt_folder(folder_path)
            elif choice == '2':
                vault.decrypt_folder()
            elif choice == '3':
                break
            else:
                print("Invalid choice, please try again.")

if __name__ == "__main__":
    system = SecurityVaultSystem()
    system.menu()


