"""
----------------------------------------------------------
Name: Fredmark Ivan D. Dizon
GitHub: https://github.com/saphiraaa
Email: fredmarkivand@gmail.com
Location: Bulacan, Philippines

Project: MIRA - CyberGuard Innovation's CLI Password Manager
GitHub Repository: https://github.com/saphiraaa/MIRA
License: MIT License

Version: 2.24.10
Release Date: 2023-12-12
Enhanced Features:
- Encryption algorithms
- Improved password generation
- Bug fixes and optimizations
- 2 Factor Auth
- Password Expiration Notification
- Password Strength Policy Adjustments
- Error Handling
----------------------------------------------------------
"""

remember = r"""

 ____________________
/                    \
|       Always       |
|      Remember      |
\____________________/
         !  !
         !  !
         L_ !
        / _)!
       / /__L
 _____/ (____)
        (____)
 _____  (____)
      \_(____)
         !  !
         !  !
         \__/
"""

blehhh = r"""
                                \\_V_//
                                \/=|=\/
                                 [=v=]
                               __\___/_____
                              /..[  _____  ]
                             /_  [ [  M /] ]
                            /../.[ [ M /@] ]
                           <-->[_[ [M /@/] ]
                          /../ [.[ [ /@/ ] ]
     _________________]\ /__/  [_[ [/@/ C] ]
    <_________________>>0---]  [=\ \@/ C / /
       ___      ___   ]/000o   /__\ \ C / /
          \    /              /....\ \_/ /
       ....\||/....           [___/=\___/
      .    .  .    .          [...] [...]
     .      ..      .         [___/ \___]
     .    0 .. 0    .         <---> <--->
  /\/\.    .  .    ./\/\      [..]   [..]
 / / / .../|  |\... \ \ \    _[__]   [__]_
/ / /       \/       \ \ \  [____>   <____]
"""

wolf = r'''
                                 ,ood8888booo,
                              ,od8           8bo,
                           ,od                   bo,
                         ,d8                       8b,
                        ,o                           o,    ,a8b
                       ,8                             8,,od8  8
                       8'                             d8'     8b
                       8                           d8'ba     aP'
                       Y,                       o8'         aP'
                        Y8,                      YaaaP'    ba                       __  ___________  ___
                         Y8o                   Y8'         88                      /  |/  /  _/ __ \/   |
                          `Y8               ,8"           `P                      / /|_/ // // /_/ / /| |
                            Y8o        ,d8P'              ba                     / /  / // // _, _/ ___ |
                       ooood8888888P"""'                  P'                    /_/  /_/___/_/ |_/_/  |_|
                    ,od                                  8                       CyberGuard Innovations
                 ,dP     o88o                           o'                               2.24.10
                ,dP          8                          8
               ,d'   oo       8                       ,8
               $    d$"8      8           Y    Y  o   8
              d    d  d8    od  ""boooooooob   d"" 8   8
              $    8  d   ood' ,   8        b  8   '8  b
              $   $  8  8     d  d8        `b  d    '8  b
               $  $ 8   b    Y  d8          8 ,P     '8  b
               `$$  Yb  b     8b 8b         8 8,      '8  o,
                    `Y  b      8o  $$o      d  b        b   $o
                     8   '$     8$,,$"      $   $o      '$o$$
                      $o$$P"                 $$o$
'''

from cryptography.fernet import Fernet
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
from threading import Thread
from termcolor import colored
from pyotp import TOTP, random_base32
import string
import random
import json
import platform

def clear_terminal():
    if os.name == "posix":
        os.system("clear")

def get_os_distribution():
    """
    Get information about the operating system distribution.

    Returns:
        str: A formatted string containing distribution information.
    """
    system_info = platform.system()

    if system_info == 'Linux':
        try:
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                distribution_info = {}
                for line in lines:
                    key, value = line.strip().split('=')
                    distribution_info[key] = value.replace('"', '')

                distribution = distribution_info.get('PRETTY_NAME', 'Unknown Distribution')
                version = distribution_info.get('VERSION_ID', 'Unknown Version')
                codename = distribution_info.get('VERSION_CODENAME', 'Unknown Codename')
                base = distribution_info.get('ID_LIKE', 'Unknown Base')
                return f"Linux Distribution: {distribution}\nVersion: {version}\nCodename: {codename}\nBase: {base}"

        except FileNotFoundError:
            return "Unable to determine distribution. /etc/os-release file not found."

    else:
        return f"Operating System: {system_info}"

def get_current_datetime():
    """Retrieve the current date and time, formatted for display."""
    current_datetime = datetime.now()
    date_str = current_datetime.strftime("%Y-%m-%d")
    time_str = current_datetime.strftime("%H:%M:%S")

    return f"Current Time: {time_str}\nDate: {date_str}"

class PasswordManager:
    MAX_LOGIN_ATTEMPTS = 4
    LOCKOUT_DURATION_SECONDS = 300
    LOCKOUT_FILE = os.environ.get('LOCKOUT_FILE', '/usr/bin/.lockout.json')
    USER_DATA_FILE = os.environ.get('USER_DATA_FILE', '/usr/bin/.user.json')
    SECFILE = os.environ.get('SECFILE', '/usr/bin/.sec.json')
    PASSFILE = os.environ.get('PASSFILE', '/usr/bin/.pass.json')

    def __init__(self):
        self.master_password = None
        self.cipher = None
        self.ph = PasswordHasher()
        expiry_thread = Thread(target=self.notify_expiry_background)
        expiry_thread.daemon = True
        expiry_thread.start()
        self.totp_secret_key = None
        self.failed_login_attempts = 0
        self.lockout_time = None
        self.load_lockout_time()
        self.replacements = {
                'a' or 'A': ['4', '@', 'á', 'ä', 'å', 'ą', 'ey', 'a', 'A'],
                'b' or 'B': ['8', '6', 'ß', 'B', 'b'],
                'c' or 'C': ['(', '<', 'ç', 'ć', 'si', 'C', 'c'],
                'd' or 'D': ['[)', '|)', 'đ', 'D', 'd'],
                'e' or 'E': ['3', '€', 'é', 'è', 'ê', 'ë', 'ę', 'E', 'e'],
                'f' or 'F': ['ph', '|=', 'ƒ', 'F', 'f'],
                'g' or 'G': ['9', '6', 'ğ', 'ji', 'G', 'g'],
                'h' or 'H': ['#', '|-|', 'ħ', 'eych', 'H', 'h'],
                'i' or 'I': ['1', '!', 'í', 'ì', 'î', 'ï', 'į', 'ay', 'I', 'i'],
                'j' or 'J': ['_|', '_]', 'й', 'j', 'J'],
                'k' or 'K': ['|<', '|{', 'ķ', 'K', 'k'],
                'l' or 'L': ['1', '|_', 'ł', 'L', 'l'],
                'm' or 'M': ['/\\/\\', '|\\/|', 'м', 'M', 'm'],
                'n' or 'N': ['|\\|', '/\\/', 'ñ', 'ń', 'ň', 'N', 'n'],
                'o' or 'O': ['0', '*', 'ó', 'ö', 'ø', 'ô', 'ő', 'O', 'o'],
                'p' or 'P': ['|>', '|D', 'þ', 'р', 'P'],
                'q' or 'Q': ['(,)', 'kw', 'q', 'Q'],
                'r' or 'R': ['2', '|?', 'г', 'ř', 'R', 'r'],
                's' or 'S': ['$', '5', 'ś', 'š', 'ş', 'ș', 'S', 's'],
                't' or 'T': ['+', '7', 'ţ', 'ť', 'T', 't'],
                'u' or 'U': ['|_|', '\\_\\', 'ü', 'ú', 'ů', 'ű', 'U', 'u'],
                'v' or 'V': ['\\/', 'V', 'v'],
                'w' or 'W': ['\\/\\/', '|/\\|', 'ш', 'щ', 'uu', 'W', 'w'],
                'x' or 'X': ['><', '%', 'ж', 'X', 'x'],
                'y' or 'Y': ['`/', 'ý', 'ÿ', 'ŷ', 'y', 'Y'],
                'z' or 'Z': ['2', '7_', 'ž', 'ź', 'ż', 'z', 'Z'],
                '0': ['o', 'ð', 'ø'],
                '1': ['i', 'l', 'ł'],
                '2': ['z', 'ż', 'ź'],
                '3': ['e', 'ę', 'ė'],
                '4': ['a', 'å', 'ä', 'à', 'á', 'â'],
                '5': ['s', 'š', 'ş', 'ș', 'ś'],
                '6': ['g', 'ğ'],
                '7': ['t', 'ţ', 'ť'],
                '8': ['b', 'ß', 'ь'],
                '9': ['g', 'ğ', 'ĝ'],
            }

    def save_lockout_time(self):
        if self.lockout_time:
            lockout_data = {'lockout_time': self.lockout_time}
            with open(self.LOCKOUT_FILE, 'w') as lockout_file:
                json.dump(lockout_data, lockout_file)

    def load_lockout_time(self):
        try:
            with open(self.LOCKOUT_FILE, 'r') as lockout_file:
                lockout_data = json.load(lockout_file)
                self.lockout_time = lockout_data.get('lockout_time')
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def increment_failed_attempts(self):
        if self.lockout_time and time.time() < self.lockout_time:
            print(colored(blehhh, "red"))
            print(colored(f"[-] Account locked. WE ALREADY TOLD YOU THAT WE DON'T ACCEPT BUGS HERE! If you are the real user, try again after {int(self.lockout_time - time.time())} seconds.", "red"))
            exit()
            return False

        self.failed_login_attempts += 1

        if self.failed_login_attempts >= self.MAX_LOGIN_ATTEMPTS:
            self.lockout_time = time.time() + self.LOCKOUT_DURATION_SECONDS
            self.save_lockout_time()
            print(colored(blehhh, "red"))
            print(colored(f"[-] Too many failed attempts. ARE YOU TRYING TO BRUTEFORCE THIS? WE DON'T ACCEPT SHITTY BUGS HERE! Account locked for {self.LOCKOUT_DURATION_SECONDS} seconds.", "red"))
            exit()
            return False

        return True

    def generate_password(self):
        """Generate a strong password based on user's choice."""
        while True:
            try:
                choice = input(colored("Choose password generation method:\n1. Random by length\n2. Custom phrase\n3. Combination of Random and Phrase\n4. Multiple Phrase\n5. Pattern\n> ", "cyan"))

                if choice == '1':
                    length = int(input(colored("Enter the desired password length: ", "yellow")))
                    password = self.generate_random_password(length)
                elif choice == '2':
                    phrase = input(colored("Enter a custom phrase: ", "yellow"))
                    password = self.generate_password_from_phrase(phrase)
                elif choice == '3':
                    length = int(input(colored("Enter the desired password length: ", "yellow")))
                    phrase = input(colored("Enter a custom phrase: ", "yellow"))
                    password = self.generate_combined_password(length, phrase)
                elif choice == '4':
                    num_phrases = int(input(colored("Enter the number of phrases: ", "yellow")))
                    phrases = [input(colored(f"Enter phrase {i + 1}: ", "yellow")) for i in range(num_phrases)]
                    password = self.generate_multi_phrase_password(phrases)
                elif choice == '5':
                    pattern = input(colored("Enter the password pattern: ", "yellow"))
                    password = self.generate_pattern_password(pattern)
                else:
                    print(colored("Invalid choice. Generating random password by length.", "red"))
                    length = int(input(colored("Enter the desired password length: ", "yellow")))
                    password = self.generate_random_password(length)

                print(colored(f"[+] Generated Password: {password}", "green"))
                break
            except ValueError as e:
                print(colored("an error occured:", e, "red"))

    def generate_combined_password(self, length, phrase):
        """Generate a password combining random characters and a user-provided phrase."""
        position = random.choice(['beginning', 'middle', 'end'])

        if position == 'beginning':
            random_part_length = length - len(phrase)
            random_part = self.generate_random_password(random_part_length)
            transformed_phrase = ''.join([random.choice(self.replacements.get(char.lower(), [char])) for char in phrase])
            password = transformed_phrase + random_part
            return password
        elif position == 'middle':
            random_part1_length = (length - len(phrase)) // 2
            random_part2_length = length - len(phrase) - random_part1_length
            random_part1 = self.generate_random_password(random_part1_length)
            random_part2 = self.generate_random_password(random_part2_length)
            transformed_phrase = ''.join([random.choice(self.replacements.get(char.lower(), [char])) for char in phrase])
            password = random_part1 + transformed_phrase + random_part2
            return password
        elif position == 'end':
            random_part_length = length - len(phrase)
            random_part = self.generate_random_password(random_part_length)
            transformed_phrase = ''.join([random.choice(self.replacements.get(char.lower(), [char])) for char in phrase])
            password = random_part + transformed_phrase
            return password

    def generate_multi_phrase_password(self, phrases):
        """Generate a password combining multiple user-provided phrases with random placement."""
        transformed_phrases = [''.join([random.choice(self.replacements.get(char.lower(), [char])) for char in phrase]) for phrase in phrases]

        random.shuffle(transformed_phrases)
        password = ''.join(transformed_phrases)
        return password

    def generate_random_password(self, length):
        """Generate a random password of the specified length."""
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def generate_password_from_phrase(self, phrase):
        """Generate a strong password based on a user-provided phrase."""
        transformed_phrase = ''.join([random.choice(self.replacements.get(char.lower(), [char])) for char in phrase])
        password = ''.join([random.choice([char.upper(), char.lower()]) for char in transformed_phrase])
        return password

    def generate_pattern_password(self, pattern):
        """Generate a password based on a user-defined pattern."""
        characters = {
            'u': string.ascii_uppercase,
            'l': string.ascii_lowercase,
            'd': string.digits,
            's': string.punctuation,
            'a': string.ascii_letters + string.digits,
        }

        password = ''.join([random.choice(characters.get(char, char)) for char in pattern])
        return password

    def enable_2fa(self):
        if self.totp_secret_key:
            print(colored("[-] 2FA is already enabled for this user.", "red"))
            return

        # Load user data
        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        self.totp_secret_key = random_base32()
        user_data['2fa_enabled'] = True
        user_data['2fa_secret_key'] = self.totp_secret_key

        # Save updated user data
        with open(self.USER_DATA_FILE, 'w') as file:
            json.dump(user_data, file)

        totp = TOTP(self.totp_secret_key)
        print(colored(f"\n[+] 2FA Enabled. Scan the QR code with your authenticator app:\n{totp.provisioning_uri('MIRA', issuer_name='CyberGuard Innovations')}", "green"))

    def verify_2fa(self, secret_key, code):
        totp = TOTP(secret_key)
        return totp.verify(code)

    def notify_expiry_background(self):
        while True:
            try:
                self.notify_expiry()
            except FileNotFoundError:
                pass
            time.sleep(86400)

    def notify_expiry(self):
        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)

            for entry in data:
                if 'expiry_at' in entry and entry['expiry_at']:
                    expiry_date = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S")
                    time_left = expiry_date - datetime.now()

                    if timedelta(days=1) <= time_left <= timedelta(days=7):
                        days_left = time_left.days
                        hours, remainder = divmod(time_left.seconds, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        print(colored(f"[!] Warning: Some of your passwords will expire in {days_left} days, {hours} hours, {minutes} minutes, and {seconds} seconds. Please update them!", 'yellow'))

                    elif time_left < timedelta(days=1) and time_left >= timedelta(seconds=0):
                        print(colored(f"[!] Alert: Some of your passwords will expired in any minute! Please update them!", 'red'))
                    elif time_left <= timedelta(seconds=0):
                        print(colored(f"[!] Alert: Some of your passwords has expired. Update is now mandatory for accessibility!", 'red'))

        except FileNotFoundError:
            pass

    def load_encryption_key(self, encryption_key):
        self.cipher = self.initialize_cipher(encryption_key)

    def initialize_cipher(self, key):
        return Fernet(key)

    def check_password_strength(self, password):
        policy = PasswordPolicy.from_names(
            length=10,
            uppercase=1,
            numbers=1,
            special=3,
        )
        result = policy.test(password)
        if result:
            print(colored("[-] Password is not strong enough (Not Added). Please follow the password policy:", "red"))
            for violation in result:
                print(colored(f"    {violation}", "red"))
            generate_strong_pass = input(colored("[*] Do you want Mira to generate a strong password for you? (y/N): ", "yellow"))
            if generate_strong_pass == 'y':
                self.generate_password()
                print(colored("[*] Now repeat the process and use that password instead.", "magenta"))
            else:
                print(colored("[-] Abort.", "red"))
            return False
        return True

    def register(self, username, master_password):
        self.increment_failed_attempts()

        if not self.check_password_strength(master_password):
            return

        if os.path.exists(self.USER_DATA_FILE) and os.path.getsize(self.USER_DATA_FILE) != 0:
            print(colored("[-] Master user already exists!!", "red"))
        else:
            self.master_password = master_password
            salt = token_bytes(16)
            salt_hex = salt.hex()
            hashed_master_password = self.ph.hash(master_password + salt_hex)
            encryption_key = Fernet.generate_key()

            # Hash the encryption key with Argon2
            ph = argon2.PasswordHasher()
            hashed_encryption_key = ph.hash(encryption_key.decode())

            user_data = {
                'username': username,
                'master_password': hashed_master_password,
                'salt': salt_hex,
                'encryption_key': hashed_encryption_key
            }
            with open(self.USER_DATA_FILE, 'w') as file:
                json.dump(user_data, file)
            print(colored("[*] For authentication just in case you forgot your master password", "magenta"))
            pet_name = getpass.getpass(colored("What is the name of your pet? ", "yellow"))
            user_location = getpass.getpass(colored("Where do you live? ", "yellow"))
            favorite_planet = getpass.getpass(colored("What is your favorite planet? ", "yellow"))
            hashed_pet_name = ph.hash(pet_name)
            hashed_user_location = ph.hash(user_location)
            hashed_favorite_planet = ph.hash(favorite_planet)
            security_data = {
                'hashed_pet_name': hashed_pet_name,
                'hashed_user_location': hashed_user_location,
                'hashed_favorite_planet': hashed_favorite_planet
            }
            with open(self.SECFILE, 'w') as security_file:
                json.dump(security_data, security_file)
                clear_terminal()
                print(colored(wolf, "blue"))
                print(colored("\n[+] Registration complete!!", "green"))
                print(colored(f"[+] Encryption key: {encryption_key.decode()}", "green"))
                print(colored("\n[*] Caution: Save your encryption key and store it somewhere safe Mira will never recover your encryption key once you forgot it!!! So please don't be stupid:)", "yellow"))

    def forgot_master_password(self, username):
        if not os.path.exists(self.SECFILE):
            print(colored("[-] Security questions not set for this user. Cannot reset master password.", "red"))
            return

        with open(self.SECFILE, 'r') as security_file:
            security_data = json.load(security_file)

        # Ask security questions for verification
        entered_pet_name = getpass.getpass(colored("What is the name of your pet? ", "yellow"))
        entered_user_location = getpass.getpass(colored("Where do you live? ", "yellow"))
        entered_favorite_planet = getpass.getpass(colored("What is your favorite planet? ", "yellow"))

        # Verify security question answers with Argon2
        ph = argon2.PasswordHasher()
        try:
            ph.verify(security_data['hashed_pet_name'], entered_pet_name)
            ph.verify(security_data['hashed_user_location'], entered_user_location)
            ph.verify(security_data['hashed_favorite_planet'], entered_favorite_planet)
        except argon2.exceptions.VerifyMismatchError:
            print(colored("[-] Incorrect answers to security questions. Resetting master password failed.", "red"))
            return

        # Ask for a new master password
        new_master_password = getpass.getpass(colored("Enter your new master password: ", "yellow"))
        re_enter = getpass.getpass(colored("Re-Enter your new master password: ", "yellow"))

        if not self.check_password_strength(new_master_password):
            return

        if new_master_password != re_enter:
            print(colored("[-] New Master Passwords Did Not Match! Resetting master password failed.", "red"))
            return

        # Update the master password in the user data file
        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        salt = token_bytes(16)
        hashed_new_master_password = self.ph.hash(new_master_password + salt.hex())
        user_data['master_password'] = hashed_new_master_password
        user_data['salt'] = salt.hex()

        with open(self.USER_DATA_FILE, 'w') as file:
            json.dump(user_data, file)

        print(colored("[+] Master password reset successful!", "green"))

    def login(self, username, entered_password, encryption_key):
        if not os.path.exists(self.USER_DATA_FILE):
            print(colored("\n[-] You have not registered. Do that first!", "red"))
        else:
            with open(self.USER_DATA_FILE, 'r') as file:
                user_data = json.load(file)

            # Check if the account is locked
            if self.lockout_time and time.time() < self.lockout_time:
                clear_terminal()
                print(colored(blehhh, "red"))
                print(colored(f"[-] Account locked. WE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(self.lockout_time - time.time())} seconds.", "red"))
                exit()
                return

            try:
                self.ph.verify(user_data['master_password'], entered_password + user_data['salt'])
            except VerifyMismatchError:
                print(colored("[-] Invalid Login credentials!!", "red"))
                if self.increment_failed_attempts():
                    return
                else:
                    return

            if username == user_data['username']:
                stored_encryption_key = user_data['encryption_key']

                # Verify the entered encryption key with Argon2
                ph = argon2.PasswordHasher()
                try:
                    ph.verify(stored_encryption_key, encryption_key)
                except argon2.exceptions.VerifyMismatchError:
                    print(colored("[-] Invalid encryption key. Login failed!", "red"))
                    if self.increment_failed_attempts():
                        return
                    else:
                        return

                self.load_encryption_key(encryption_key.encode())

                if '2fa_enabled' in user_data and user_data['2fa_enabled']:
                    code = getpass.getpass(colored("Enter the 6-digit code from your authenticator app: ", "yellow"))
                    if not self.verify_2fa(user_data['2fa_secret_key'], code):
                        print(colored("[-] Invalid 2FA code. Login failed!", "red"))
                        if self.increment_failed_attempts():
                            return
                        else:
                            return

                print(colored("[+] Login Successful..", "green"))
                time.sleep(3)
                clear_terminal()
                print(colored(wolf, "blue"))
                self.master_password = entered_password
                self.main_menu()

            else:
                print(colored("[-] Invalid Login credentials!!", "red"))
                if self.increment_failed_attempts():
                    return
                else:
                    return

    def show_expiry_status(self):
        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)

            platform_url = input(colored("Enter the URL of the platform: ", "yellow"))
            usernames_status = []

            for entry in data:
                if entry['website'] == platform_url:
                    expiry_status, remaining_time = self.check_expiry_status(entry.get('expiry_at'))
                    usernames_status.append({'username': entry['username'], 'status': expiry_status, 'remaining_time': remaining_time})

            if usernames_status:
                print(colored(f"[+] Available Users for {platform_url}", "green"))
                print(colored("\nUsername".ljust(21) + "Status".ljust(25) + "Remaining Time", "cyan"))
                print(colored("----------".ljust(20) + "----------".ljust(25) + "--------------", "cyan"))
                for user_status in usernames_status:
                    print(f"{colored(user_status['username'].ljust(20), 'cyan')}{user_status['status'].ljust(34)}{colored(user_status['remaining_time'], 'cyan')}")
            else:
                print(colored("[-] No matching entries found for the specified platform.", "red"))

        except FileNotFoundError:
            print(colored("[-] No passwords saved. Show expiry status failed!", "red"))

    def check_expiry_status(self, expiry_date):
        if expiry_date:
            expiry_date = datetime.strptime(expiry_date, "%Y-%m-%d %H:%M:%S")
            time_left = expiry_date - datetime.now()

            if timedelta(days=1) <= time_left <= timedelta(days=7):
                return colored("Nearly Expired", "yellow"), str(time_left)
            elif time_left < timedelta(days=1) and time_left >= timedelta(seconds=0):
                return colored("About to Expire", "magenta"), str(time_left)
            elif time_left <= timedelta(seconds=0):
                return colored("Expired", "red"), colored("0 days, 0 hours, 0 minutes, 0 seconds", "red")
            else:
                days_left = time_left.days
                hours, remainder = divmod(time_left.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                remaining_time = f"{days_left} days, {hours} hours, {minutes} minutes, {seconds} seconds"
                return colored("Updated", "green"), str(time_left)
        return "OK", "N/A"

    def main_menu(self):
        while True:
            choice = input(colored("MIRA> ", "blue"))

            if choice == "":
                continue

            elif choice == 'add':
                website = input(colored("Platform: ", "yellow"))
                username = input(colored("Username: ", "yellow"))
                password = getpass.getpass(colored("Password: ", "yellow"))
                self.add_password(website, username, password)

                self.notify_expiry()

            elif choice == 'get':
                website = input(colored("Platform: ", "yellow"))
                username = input(colored("Username: ", "yellow"))
                decrypted_password = self.get_password(website, username)

                try:
                    with open(self.PASSFILE, 'r') as file:
                        data = json.load(file)

                    for entry in data:
                        if entry['website'] == website and entry['username'] == username and 'expiry_at' in entry and entry['expiry_at']:
                            expiry_date = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S")
                            if datetime.now() > expiry_date:
                                response = input(colored("[*] Password has expired. Do you want to update the password or delete the website? (U/D): ", "yellow")).lower()
                                if response == 'u':
                                    new_password = getpass.getpass(colored("Enter the updated password: ", "yellow"))

                                    if not self.check_password_strength(new_password):
                                        return

                                    entry['password'] = self.encrypt_password(new_password)
                                    entry['expiry_at'] = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

                                    with open(self.PASSFILE, 'w') as file:
                                        json.dump(data, file, indent=4)

                                    decrypted_password = self.decrypt_password(entry['password'])
                                    if decrypted_password:
                                        print(colored("[+] Key Content Update Successfully!", "green"))
                                        print(colored(f"[+] Updated Key Content: {decrypted_password}", "green"))
                                    else:
                                        print(colored("[-] Password has expired. Please update your password.", "red"))
                                    return

                                elif response == 'd':
                                    caution = input(colored("[*] Caution: Once you remove it, it will be permanently deleted to your system. Are you sure you want to proceed? (y/N): ", "yellow"))
                                    if caution == 'n':
                                        print(colored("Abort.", "red"))
                                        return
                                    elif caution == 'y':
                                        data = [e for e in data if not (e['website'] == website and e['username'] == username)]
                                        with open(self.PASSFILE, 'w') as file:
                                            json.dump(data, file, indent=4)

                                        print(colored("[-] Website permanently deleted.", "red"))
                                        return
                    else:
                        if decrypted_password is not None:
                            print(colored(f"[+] Key Content: {decrypted_password}", "green"))
                        elif response == 'u':
                            print(colored("[*] Remember to always update your password.", "yellow"))
                        elif response == 'd':
                            print(colored("[*] We don't want you to get breached that's why we have this.", "yellow"))
                        else:
                            print(colored("[-] Password not found! Did you save the password?", "red"))

                except FileNotFoundError:
                    print(colored("[-] No passwords has been saved yet!", "red"))

            elif choice == 'changemast':
                self.change_master_password()

            elif choice == 'generate':
                self.generate_password()

            elif choice == 'delpass':
                self.delete_password()

            elif choice == 'changepass':
                website = input(colored("Enter website for which you want to change the password: ", "yellow"))
                username = input(colored("Enter username for which you want to change the password: ", "yellow"))
                self.change_password(website, username)

            elif choice == 'enable2fa':
                self.enable_2fa()

            elif choice == 'showexp':
                self.show_expiry_status()

            elif choice == 'reset':
                caution = input(colored("[*] Caution: After attempting to do reset, all of the data including your passwords and your master user in mira will be deleted permanently! Are you sure that you want to proceed? (y/N): ", "yellow"))
                if caution == 'y':
                    master_password = getpass.getpass(colored("Master password: ", "yellow"))
                    with open(self.USER_DATA_FILE, 'r') as file:
                        user_data = json.load(file)

                    stored_master_password = user_data['master_password']
                    salt = user_data['salt']

                    try:
                        self.ph.verify(stored_master_password, master_password + salt)
                    except VerifyMismatchError:
                        print(colored("\n[-] Incorrect current master password. Reset prcedure failed!", "red"))
                        return

                    if os.path.exists(self.LOCKOUT_FILE):
                        os.remove(self.LOCKOUT_FILE)
                    else:
                        pass
                    if os.path.exists(self.PASSFILE):
                        os.remove(self.PASSFILE)
                    else:
                        pass
                    if os.path.exists(self.SECFILE):
                        os.remove(self.SECFILE)
                    else:
                        pass
                    os.remove(self.USER_DATA_FILE)
                    print(colored("[+] All data has been successfully removed.", "green"))
                    start_again = input(colored("Do you want to start a new account? (y/N): ", "yellow"))
                    if start_again == 'y':
                        username = input(colored("New Username: ", "yellow"))
                        master_password = getpass.getpass(colored("New master password: ", "yellow"))
                        re_enter = getpass.getpass(colored("Re-enter master password: ", "yellow"))
                        if re_enter != master_password:
                            print(colored("[-] Master Password Did Not Match! QUITTING!", "red"))
                        else:
                            password_manager.register(username, master_password)
                            break
                    else:
                        break
                else:
                    print(colored("[-] Abort.", "red"))

            elif choice == 'lout':
                self.logout()
                break

            elif choice == 'h' or choice == 'help':
                print(colored("Available Commands:\n'add' - Add a new password for the desired platform\n'get' - Display the plaintext version of the password for the desired platform\n'changemast' - Change the masterkey (Recommended for security)\n'deletepass' - Delete a saved password\n'enable2fa' - Enable Two-Factor Authentication for added security\n'changepass' - Change the password for the desired platform.\n'generate' - Generate a strong password.\n'showexp' - List all the usernames and their status of a specific platform.\n'reset' - Delete all the data including the user account permanently (Be cautious with this command! It can result for a permanent data loss!)\n'lout' - Logout\n'exit' - Terminate MIRA\n\nSecurity Recommendations:\n- Regularly check for password expiration using 'get' command.\n- Keep your master password and encryption key secure.\n- Enable Two-Factor Authentication for an additional layer of security.\n\nNote: Password strength policy requires at least 8 characters with uppercase, numbers, and special characters.\n", "cyan"))

            elif choice == 'exit':
                self.logout()
                exit()

            else:
                print(colored("Invalid Option", "red"))

    def add_password(self, website, username, password):
        if not self.check_password_strength(password):
            return

        if not website.startswith('http://') and not website.startswith('https://'):
            print(colored("[-] Provide a platform in URL form please.", "red"))
            return

        if not os.path.exists(self.PASSFILE):
            data = []
        else:
            try:
                with open(self.PASSFILE, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []
            except FileNotFoundError:
                pass

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
            with open(self.PASSFILE, 'w') as file:
                json.dump(data, file, indent=4)
            print(colored("[+] Password added!", "green"))
        else:
            print(colored("[-] Password not added. Please choose a stronger password.", "red"))

    def get_password(self, website, username):
        if not os.path.exists(self.PASSFILE):
            return None

        try:
            with open(self.PASSFILE, 'r') as file:
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
        website = input(colored("Platform for the password you want to delete: ", "yellow"))
        username = input(colored("Username for the password you want to delete: ", "yellow"))
        master_pass = getpass.getpass(colored("Current master password: ", "yellow"))

        if not os.path.exists(self.PASSFILE):
            print(colored("[-] No passwords saved. Deletion failed!", "red"))
            return

        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        stored_master_password = user_data['master_password']
        salt = user_data['salt']

        try:
            self.ph.verify(stored_master_password, master_pass + salt)
        except VerifyMismatchError:
            print(colored("\n[-] Incorrect current master password. Delete password failed!", "red"))
            return

        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for entry in data:
            if entry['website'] == website and entry['username'] == username:
                data.remove(entry)
                with open(self.PASSFILE, 'w') as file:
                    json.dump(data, file, indent=4)
                print(colored("[+] Password deleted successfully!\n", "green"))
                return

        print(colored("[-] Password not found! Deletion failed!", "red"))

    def change_password(self, website, username):
        data = []

        if not os.path.exists(self.PASSFILE):
            print(colored("[-] No passwords saved!", "red"))
            return

        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            pass


        current_password = getpass.getpass(colored("Current password for the given platform and username: ", "yellow"))

        # Verify the entered current password
        decrypted_password = self.get_password(website, username)

        if decrypted_password is not None and current_password == decrypted_password:
            new_password = getpass.getpass(colored("New password: ", "yellow"))
            re_enter = getpass.getpass(colored("Re-Enter new password: ", "yellow"))

            if not self.check_password_strength(new_password):
                return

            if new_password != re_enter:
                print(colored("[-] New Passwords Did Not Match! Change password failed!", "red"))
                return
            encrypted_new_password = self.encrypt_password(new_password)

            try:
                with open(self.PASSFILE, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []

            for entry in data:
                if entry['website'] == website and entry['username'] == username:
                    entry['password'] = encrypted_new_password
                    entry['expiry_at'] = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

                    with open(self.PASSFILE, 'w') as file:
                        json.dump(data, file, indent=4)

                    decrypted_password = self.decrypt_password(entry['password'])
                    if decrypted_password:
                        print(colored("[+] Password updated successfully!", "green"))
                        print(colored(f"[+] Updated Password: {decrypted_password}", "green"))
                    else:
                        print(colored("[-] Password update failed.", "red"))
                    return

        elif website not in [entry['website'] for entry in data]:
            print(colored("[-] This platform is not available on your vault.", "red"))
        elif username not in [entry['username'] for entry in data]:
            print(colored("[-] This username doesn't exist for that platform.", "red"))
        else:
            print(colored("[-] Incorrect current password. Change password failed!", "red"))

    def encrypt_password(self, password):
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        return self.cipher.decrypt(encrypted_password.encode()).decode()

    def view_websites(self):
        try:
            with open(self.PASSFILE, 'r') as data:
                view = json.load(data)
                websites = [(x['website'], x['username'], x['password'], x['added_at'], x['expiry_at']) for x in view]
                print("\nWebsites you saved:\n")
                print(tabulate(websites, headers=["Platforms", "User", "Key Content", "Added At", "Expiry At"], tablefmt="pretty"))
                print('\n')
        except FileNotFoundError:
            print(colored("[-] You have not saved any passwords!", "red"))

    def change_master_password(self):
        current_password = getpass.getpass(colored("Current master password: ", "yellow"))
        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        stored_master_password = user_data['master_password']
        salt = user_data['salt']

        try:
            self.ph.verify(stored_master_password, current_password + salt)
        except VerifyMismatchError:
            print(colored("\n[-] Incorrect current master password. Change password failed!", "red"))
            return

        new_password = getpass.getpass(colored("New master password: ", "yellow"))
        re_enter = getpass.getpass(colored("Re-Enter your new master password: ", "yellow"))

        if not self.check_password_strength(new_password):
            return

        if new_password != re_enter:
            print(colored("[-] New Master Passwords Did Not Match! Change password failed!", "red"))
            return

        hashed_new_password = self.ph.hash(new_password + salt)
        user_data['master_password'] = hashed_new_password

        with open(self.USER_DATA_FILE, 'w') as file:
            json.dump(user_data, file)

        self.master_password = new_password
        print(colored("[+] Master password changed successfully!", "green"))
        print(colored(f"[+] New Master Password: {re_enter}", "green"))

    def logout(self):
        self.master_password = None
        self.cipher = None
        print(colored("[+] Logged out!", "cyan"))

if __name__ == '__main__':
    if not 'SUDO_UID' in os.environ.keys():
        print(colored("[-] Mira requires an elevated privileges. QUITTING!", "red"))
        exit()
    else:
        clear_terminal()
        current_datetime_info = get_current_datetime()
        os_distribution_info = get_os_distribution()
        print(colored(os_distribution_info, "blue"))
        time.sleep(2)
        print(colored(current_datetime_info, "blue"))
        time.sleep(2)
        print(colored("[+] Starting Mira Password Manager.....", "blue"))
        password_manager = PasswordManager()
        time.sleep(20)
        clear_terminal()
        print(colored(wolf, "blue"))
        while True:
            try:
                choice = input(colored("MIRA> ", "blue"))

                if choice == "":
                    continue

                elif choice == 'regis':
                    if os.path.exists(password_manager.USER_DATA_FILE) and os.path.getsize(password_manager.USER_DATA_FILE) != 0:
                        print(colored("[-] Master user already exists!!", "red"))
                    else:
                        username = input(colored("New Username: ", "yellow"))
                        master_password = getpass.getpass(colored("New master password: ", "yellow"))
                        re_enter = getpass.getpass(colored("Re-Enter master password: ", "yellow"))
                        if re_enter != master_password:
                            print(colored("[-] Master Password Did Not Match! QUITTING!", "red"))
                        else:
                            password_manager.register(username, master_password)

                elif choice == 'log':
                    if os.path.exists(password_manager.USER_DATA_FILE):
                        username = input(colored("Username: ", "yellow"))
                        master_password = getpass.getpass(colored("Master password: ", "yellow"))
                        encryption_key = getpass.getpass(colored("Encryption key: ", "yellow"))
                        password_manager.login(username, master_password, encryption_key)
                    else:
                        print(colored("[-] You have not registered. Please do that.", "red"))

                elif choice == 'showpltf':
                    password_manager.view_websites()

                elif choice == 'help' or choice == 'h':
                    print(colored("'log'- Login\n'regis'- Register\n'showpltf'- Show Saved Passwords\n'quit'- Quit\n'h'- Help", "cyan"))

                elif choice == 'forgot':
                    username = input(colored("Username: ", "yellow"))
                    password_manager.forgot_master_password(username)

                elif choice == 'quit':
                    print(colored("\n[-]Exiting Mira.....", "red"))
                    time.sleep(3)
                    clear_terminal()
                    print(colored(remember, "cyan"))
                    print(colored("Creating a password is like crafting a witty joke: it should be unique, memorable, and leave hackers scratching their heads. So, don't be shy to sprinkle a dash of humor into your password game – after all, laughter is the best encryption!", "cyan"))
                    exit()

                elif choice == 'showexp':
                    password_manager.show_expiry_status()

                else:
                    print(colored("[-] Invalid Option", "red"))

            except KeyboardInterrupt:
                print(colored("\n[-] Exiting Mira.....", "red"))
                time.sleep(3)
                clear_terminal()
                print(colored(remember, "cyan"))
                print(colored("Creating a password is like crafting a witty joke: it should be unique, memorable, and leave hackers scratching their heads. So, don't be shy to sprinkle a dash of humor into your password game – after all, laughter is the best encryption!", "cyan"))
                break