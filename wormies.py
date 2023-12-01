from cryptography.fernet import Fernet
import json
import os
import getpass
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from secrets import token_bytes
from tabulate import tabulate
import argon2
import time
from password_strength import PasswordPolicy
from datetime import datetime, timedelta

# Constants
USER_DATA_FILE = '/usr/bin/.user_data.json'
PASSWORDS_FILE = '/usr/bin/.passwords.json'

tool = """
     __  ___________  ___
    /  |/  /  _/ __ \/   |
   / /|_/ // // /_/ / /| |
  / /  / // // _, _/ ___ |
 /_/  /_/___/_/ |_/_/  |_|
<<<CyberGuard Innovations>>>
"""

def clear_terminal():
    if os.name == "posix":
        os.system("clear")

class PasswordManager:
    def __init__(self):
        self.master_password = None
        self.cipher = None
        self.ph = PasswordHasher()

    def load_encryption_key(self, encryption_key):
        self.cipher = self.initialize_cipher(encryption_key)

    def initialize_cipher(self, key):
        return Fernet(key)

    def check_password_strength(self, password):
        policy = PasswordPolicy.from_names(
            length=8,
            uppercase=1,
            numbers=1,
            special=1,
        )
        result = policy.test(password)
        if result:
            print("\n[-] Password is not strong enough (Not Added). Please follow the password policy:")
            for violation in result:
                print(f"    {violation}")
            print("\n")
            return False
        return True

    def register(self, username, master_password):
        if os.path.exists(USER_DATA_FILE) and os.path.getsize(USER_DATA_FILE) != 0:
            print("\n[-] Master user already exists!!")
        else:
            self.master_password = master_password
            salt = token_bytes(16)
            salt_hex = salt.hex()
            hashed_master_password = self.ph.hash(master_password + salt_hex)
            encryption_key = Fernet.generate_key()  # Generate a new encryption key

            # Hash the encryption key with Argon2
            ph = argon2.PasswordHasher()
            hashed_encryption_key = ph.hash(encryption_key.decode())

            user_data = {
                'username': username,
                'master_password': hashed_master_password,
                'salt': salt_hex,
                'encryption_key': hashed_encryption_key
            }
            with open(USER_DATA_FILE, 'w') as file:
                json.dump(user_data, file)
                print("\n[+] Registration complete!!")
                print(f"[+] Encryption key: {encryption_key.decode()}")
                print("[*]Caution: Save your encryption key and store it somewhere safe this code will never recover your encryption key once you forgot it!!!")

    def login(self, username, entered_password, encryption_key):
        if not os.path.exists(USER_DATA_FILE):
            print("\n[-] You have not registered. Please do that.\n")
        else:
            with open(USER_DATA_FILE, 'r') as file:
                user_data = json.load(file)

            # Verify entered password
            try:
                self.ph.verify(user_data['master_password'], entered_password + user_data['salt'])
            except VerifyMismatchError:
                print("\n[-] Invalid Login credentials. Please use the credentials you used to register.\n")
                return

            if username == user_data['username']:
                stored_encryption_key = user_data['encryption_key']

                # Verify the entered encryption key with Argon2
                ph = argon2.PasswordHasher()
                try:
                    ph.verify(stored_encryption_key, encryption_key)
                except argon2.exceptions.VerifyMismatchError:
                    print("\n[-] Invalid encryption key. Login failed!\n")
                    return

                self.load_encryption_key(encryption_key.encode())
                print("\n[+] Login Successful..\n")
                time.sleep(3)
                clear_terminal()
                print(tool)
                self.master_password = entered_password
                self.main_menu()
            else:
                print("\n[-] Invalid Login credentials. Please use the credentials you used to register.\n")

    def main_menu(self):
        while True:
            choice = input("MIRA> ")

            if choice == "":
                continue

            elif choice == 'add':
                website = input("Enter website: ")
                username = input("Enter Username: ")
                password = getpass.getpass("Enter password: ")
                self.add_password(website, username, password)

            elif choice == 'get':
                website = input("Enter website: ")
                username = input("Enter Username: ")
                decrypted_password = self.get_password(website, username)

                with open(PASSWORDS_FILE, 'r') as file:
                    data = json.load(file)

                for entry in data:
                    if entry['website'] == website and entry['username'] == username and 'expiry_at' in entry and entry['expiry_at']:
                        expiry_date = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S")
                        if datetime.now() > expiry_date:
                            response = input("[-] Password has expired. Do you want to update the password or delete the website? (U/D): ").lower()
                            if response == 'u':
                                new_password = getpass.getpass("Enter the updated password: ")

                                entry['password'] = self.encrypt_password(new_password)
                                entry['expiry_at'] = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

                                with open(PASSWORDS_FILE, 'w') as file:
                                    json.dump(data, file, indent=4)

                                decrypted_password = self.decrypt_password(entry['password'])
                                if decrypted_password:
                                    print(f"\n[+] Updated Key Content: {decrypted_password}\n")
                                else:
                                    print("\n[-] Password has expired. Please update your password.\n")
                                break

                            elif response == 'd':
                                caution = input("[*] Caution: Once you remove it, it will be permanently deleted to your system. Are you sure you want to proceed? (y/N): ")
                                if caution == 'n':
                                    print("Abort.")
                                    break
                                elif caution == 'y':
                                    data = [e for e in data if not (e['website'] == website and e['username'] == username)]
                                    with open(PASSWORDS_FILE, 'w') as file:
                                        json.dump(data, file, indent=4)

                                    print("\n[-] Website permanently deleted.\n")
                                    break
                else:
                    if decrypted_password is not None:
                        print(f"\n[+] Key Content: {decrypted_password}")
                    else:
                        print("\n[-] Password not found! Did you save the password? Use option 3 to see the websites you saved.\n")

            elif choice == 'changemast':
                self.change_master_password()

            elif choice == 'deletepassword':
                self.delete_password()

            elif choice == 'lout':
                self.logout()
                break

            elif choice == 'h' or choice == 'help':
                print("'add' - Add new password for the desired platform\n'get' - Display the plaintext version of password for the desired platform\n'changemast' - Change the masterkey\n'deletepassword' - Delete a saved password\n'lout' - logout\n'exit' - terminate mira")

            elif choice == 'exit':
                self.logout()
                exit()

            else:
                print("Invalid Option")

    def add_password(self, website, username, password):
        if not self.check_password_strength(password):
            return

        if not os.path.exists(PASSWORDS_FILE):
            data = []
        else:
            try:
                with open(PASSWORDS_FILE, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []

        salt = token_bytes(16)
        if self.check_password_strength(password):
            encrypted_password = self.encrypt_password(password)
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            password_entry = {
                'website': website,
                'username': username,
                'password': encrypted_password,
                'added_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'expiry_at': (datetime.strptime(current_time, '%Y-%m-%d %H:%M:%S') + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

            }
            data.append(password_entry)
            with open(PASSWORDS_FILE, 'w') as file:
                json.dump(data, file, indent=4)
            print("\n[+] Password added!\n")
        else:
            print("\n[-] Password not added. Please choose a stronger password.\n")

    def get_password(self, website, username):
        if not os.path.exists(PASSWORDS_FILE):
            return None

        try:
            with open(PASSWORDS_FILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for entry in data:
            if entry['website'] == website and entry['username'] == username:
                if 'expiry_at' in entry and entry['expiry_at']:
                    expiry_date = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S")
                    if datetime.now() > expiry_date:
                        return None

                decrypted_password = self.decrypt_password(entry['password'])
                return decrypted_password

        return None

    def delete_password(self):
        website = input("Enter website for the password you want to delete: ")
        username = input("Enter username for the password you want to delete: ")

        if not os.path.exists(PASSWORDS_FILE):
            print("\n[-] No passwords saved. Deletion failed!\n")
            return

        try:
            with open(PASSWORDS_FILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for entry in data:
            if entry['website'] == website and entry['username'] == username:
                data.remove(entry)
                with open(PASSWORDS_FILE, 'w') as file:
                    json.dump(data, file, indent=4)
                print("\n[+] Password deleted successfully!\n")
                return

        print("\n[-] Password not found! Deletion failed!\n")

    def encrypt_password(self, password):
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        return self.cipher.decrypt(encrypted_password.encode()).decode()

    def view_websites(self):
        try:
            with open(PASSWORDS_FILE, 'r') as data:
                view = json.load(data)
                websites = [(x['website'], x['username'], x['password'], x['added_at'], x['expiry_at']) for x in view]
                print("\nWebsites you saved:\n")
                print(tabulate(websites, headers=["Platforms", "User", "Key Content", "Added At", "Expiry At"], tablefmt="pretty"))
                print('\n')
        except FileNotFoundError:
            print("\n[-] You have not saved any passwords!\n")

    def change_master_password(self):
        current_password = getpass.getpass("Enter your current master password: ")
        with open(USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        stored_master_password = user_data['master_password']
        salt = user_data['salt']

        try:
            self.ph.verify(stored_master_password, current_password + salt)
        except VerifyMismatchError:
            print("\n[-] Incorrect current master password. Change password failed!\n")
            return

        new_password = getpass.getpass("Enter your new master password: ")
        re_enter = getpass.getpass("Re-Enter your new master password: ")

        if new_password != re_enter:
            print("New Master Passwords Did Not Match! Change password failed!")
            return

        hashed_new_password = self.ph.hash(new_password + salt)
        user_data['master_password'] = hashed_new_password

        with open(USER_DATA_FILE, 'w') as file:
            json.dump(user_data, file)

        self.master_password = new_password
        print("\n[+] Master password changed successfully!\n")

    def logout(self):
        self.master_password = None
        self.cipher = None
        print("\n[+] Logged out!\n")

if __name__ == '__main__':
    password_manager = PasswordManager()
    clear_terminal()
    print("\n[+] Starting Mira Password Manager.....")
    time.sleep(10)
    clear_terminal()
    print(tool)
    while True:
        try:
            choice = input("MIRA> ")

            if choice == "":
                continue

            elif choice == 'regis':
                if os.path.exists(USER_DATA_FILE) and os.path.getsize(USER_DATA_FILE) != 0:
                    print("\n[-] Master user already exists!!")
                else:
                    username = input("Enter your username: ")
                    master_password = getpass.getpass("Enter your master password: ")
                    re_enter = getpass.getpass("Re-Enter your master password: ")
                    if re_enter != master_password:
                        print("Master Password Did Not Match! QUITTING!")
                    else:
                        password_manager.register(username, master_password)

            elif choice == 'log':
                if os.path.exists(USER_DATA_FILE):
                    username = input("Enter your username: ")
                    master_password = getpass.getpass("Enter your master password: ")
                    encryption_key = getpass.getpass("Enter your encryption key: ")
                    password_manager.login(username, master_password, encryption_key)
                else:
                    print("\n[-] You have not registered. Please do that.\n")

            elif choice == 'showpltf':
                password_manager.view_websites()

            elif choice == 'help' or choice == 'h':
                print("'log'- Login\n'regis'- Register\n'showpltf'- Show Saved Passwords\n'quit'- Quit\n'h'- Help")

            elif choice == 'quit':
                exit()

            else:
                print("Invalid Option")

        except KeyboardInterrupt:
            print("\nExiting Mira.....")
            break
