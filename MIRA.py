#!/usr/bin/env python3

about = """
---------------------------------------------------------------
Author: Fredmark Ivan D. Dizon
GitHub: https://github.com/veilwr4ith
Email: fredmarkivand@gmail.com

Project: MIRA - GiraSec Solutions's CLI Password Manager
GitHub Repository: https://github.com/GiraSec/MIRA
License: MIT License

Version: 2.1.11
Release Date: 2024-01-25
                                                            
New Features:                                                 
- Debit/Credit Card PINs are now supported 
- SSH Keys are now supported
- Password Strength Checker
- Bug fixes and optimizations                                 
- Password Expiration for Card PINs (2mnths)                   
- Mnemonic Option for encryption key

For concerns and Issues please email us here:
girasesolutions@gmail.com
---------------------------------------------------------------
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
                    ,od                                  8                       GiraSec Solutions
                 ,dP     o88o                           o'                               2.1.11
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from mnemonic import Mnemonic
import base64
import os
import getpass
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from secrets import token_bytes
import argon2
import time
from password_strength import PasswordPolicy
from datetime import datetime, timedelta
from threading import Thread
from termcolor import colored
from pyotp import TOTP, random_base32
from functools import wraps
import string 
import random
import json
import platform
import sys
import paramiko
import io
import validators
import uuid

def clear_terminal():
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nt":
        os.system("cls")

def get_os_distribution():
    """
    This function, get_os_distribution(), retrieves information about the operating system.
    For Linux, it reads /etc/os-release to gather distribution details.
    For macOS, it utilizes platform.mac_ver().
    For Windows, it uses platform.version().
    Returns formatted strings with relevant OS details.
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
                return f"Linux Distribution: {distribution}\nVersion: {version}\nCodename: {codename}\nBase: {base}\nArchitecture: {platform.architecture()[0]}"

        except FileNotFoundError:
            return "Unable to determine distribution. /etc/os-release file not found."

    elif system_info == 'Darwin':
        version, _, _ = platform.mac_ver()
        return f"macOS Version: {version}\nArchitecture: {platform.architecture()[0]}"

    elif system_info == 'Windows':
        version = platform.version()
        return f"Windows Version: {version}\nArchitecture: {platform.architecture()[0]}"

    else:
        return f"Operating System: {system_info}"

def get_python_version():
    """
    Returns python's current version
    """
    return f"Python Version: {platform.python_version()}"

def check_linux_privileges():
    """
    Check for elevated privileges. For LINUX
    """
    if 'SUDO_UID' in os.environ.keys() or os.getenv('USER') == 'root':
        return True
    return False

def is_admin():
    """
    Check for elavated privileges. For WINDOWS
    """
    if platform.system() == 'Windows':
        try:
            from ctypes import windll
            return windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        return False

def check_windows_privileges():
    return is_admin()

def get_current_datetime():
    """
    Retrieve the current date and time, formatted for display.
    """
    current_datetime = datetime.now()
    date_str = current_datetime.strftime("%Y-%m-%d")
    time_str = current_datetime.strftime("%H:%M:%S")

    return f"Current Time: {time_str}\nDate: {date_str}"

def loading_animation(duration=20):
    patterns = ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]"]
    num_patterns = len(patterns)
    start_time = time.time()

    while time.time() - start_time < duration:
        for i in range(num_patterns):
            sys.stdout.write("\r" + colored("[*] Starting MIRA Password Manager" + patterns[i % num_patterns], "blue"))
            sys.stdout.flush()
            time.sleep(0.2)

    sys.stdout.flush()

class PasswordManager:
    MAX_LOGIN_ATTEMPTS = 4 
    LOCKOUT_DURATION_SECONDS = 300
    """--------File Paths for specific Operating Systems--------"""
    if os.name == "posix":
        LOCKOUT_FILE = os.environ.get('LOCKOUT_FILE', '/etc/.lockout')
        USER_DATA_FILE = os.environ.get('USER_DATA_FILE', '/etc/.user')
        PASSFILE = os.environ.get('PASSFILE', '/etc/.pass')
        API = os.environ.get('API', '/etc/.api')
        CARD_PIN_FILE = os.environ.get('CARD_PIN_FILE', '/etc/.card')
        SSH = os.environ.get('SSH', '/etc/.ssh')
    elif os.name == "nt":
        program_files_dir = os.environ.get('ProgramFiles', 'C:\\Program Files')
        app_folder_name = 'Mira'
        app_folder_path = os.path.join(program_files_dir, app_folder_name)
        os.makedirs(app_folder_path, exist_ok=True)
        LOCKOUT_FILE = os.path.join(app_folder_path, 'lockout')
        USER_DATA_FILE = os.path.join(app_folder_path, 'user_data')
        PASSFILE = os.path.join(app_folder_path, 'pass')
        API = os.path.join(app_folder_path, 'api')
        CARD_PIN_FILE = os.path.join(app_folder_path, 'card')
        SSH = os.environ.get('SSH', '/etc/.ssh')

    def __init__(self):
        """--------Initializers--------"""
        self.master_password = None
        self.cipher = None
        self.ph = PasswordHasher()
        expiry_thread = Thread(target=self.notify_expiry_background)
        pin_expiry_thread = Thread(target=self.notify_pin_expiry_background)
        pin_expiry_thread.daemon = True
        expiry_thread.daemon = True
        expiry_thread.start()
        pin_expiry_thread.start()
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
        """
        Saves the lockout time to a file in JSON format if lockout_time is set. It creates a dictionary with 'lockout_time' as the key and the lockout time value, then writes it to the LOCKOUT_FILE using json.dump().
        """
        if self.lockout_time:
            lockout_data = {'lockout_time': self.lockout_time}
            with open(self.LOCKOUT_FILE, 'w') as lockout_file:
                json.dump(lockout_data, lockout_file)

    def load_lockout_time(self):
        """
        Attempts to load lockout time from the LOCKOUT_FILE. It reads the file, extracts 'lockout_time' from the JSON data, and sets it to self.lockout_time. If the file is not found or there is a JSON decoding error, it gracefully handles the exception.
        """
        try:
            with open(self.LOCKOUT_FILE, 'r') as lockout_file:
                lockout_data = json.load(lockout_file)
                self.lockout_time = lockout_data.get('lockout_time')
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def increment_failed_attempts(self):
        """
        Handles incrementing the count of failed login attempts. If the lockout_time is set and the current time is less than the lockout_time, it prints a message and exits. Otherwise, it increments the failed login attempts counter and checks if it exceeds the maximum allowed attempts. If exceeded, it sets a lockout time and prints a message before exiting. Otherwise, it returns True.
        """
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
        """
        Generate a strong password based on user's choice.
        """
        while True:
            try:
                choice = input(colored("[**] Choose password generation method:\n1. Random by length\n2. Custom phrase\n3. Combination of Random and Phrase\n4. Multiple Phrase\n5. Pattern\n> ", "cyan"))

                if choice == '1':
                    try:
                        length = int(input(colored("[*] Enter the desired password length: ", "yellow")))
                    except ValueError:
                        length = 30
                        print(colored(f"[**] No length provided!! (default: {length})", "magenta"))
                    password = self.generate_random_password(length)
                elif choice == '2':
                    phrase = input(colored("[*] Enter a custom phrase: ", "yellow"))
                    if not phrase:
                        print(colored("[**] No phrase provided!! using default phrase", "magenta"))
                        phrase = 'mirathebestpasswordmanager'
                    else:
                        phrase = str(phrase)
                    password = self.generate_password_from_phrase(phrase)
                elif choice == '3':
                    try:
                        length = int(input(colored("[*] Enter the desired password length: ", "yellow")))
                    except ValueError:
                        length = 30
                        print(colored(f"[**] No length provided!! (default: {length})", "magenta"))
                    phrase = input(colored("[*] Enter a custom phrase: ", "yellow"))
                    if not phrase:
                        print(colored("[**] No phrase provided, using default phrase!!", "magenta"))
                        phrase = 'mirathebestpasswordmanager'
                    else:
                        phrase = str(phrase)
                    password = self.generate_combined_password(length, phrase)
                elif choice == '4':
                    try:
                        num_phrases = int(input(colored("[*] Enter the number of phrases: ", "yellow")))
                    except ValueError:
                        num_phrases = 4
                        print(colored(f"[**] No number of phrases provided!! (default: {num_phrases})", "magenta"))
                    phrases = [input(colored(f"[*] Enter phrase {i + 1}: ", "yellow")) for i in range(num_phrases)]
                    password = self.generate_multi_phrase_password(phrases)
                elif choice == '5':
                    pattern = input(colored("[*] Enter the password pattern: ", "yellow"))
                    if not pattern:
                        pattern = 'ulsudauullddaassuldsa'
                        print(colored(f"[**] No pattern provided!! (default: {pattern})", "magenta"))
                    else:
                        pattern = str(pattern)
                    password = self.generate_pattern_password(pattern)
                else:
                    print(colored("[-] Invalid choice. Generating random password by length.", "red"))
                    try:
                        length = int(input(colored("[-] Enter the desired password length: ", "yellow")))
                    except ValueError:
                        length = 30
                        print(colored(f"[**] No length provided!! (default: {length}).", "magenta"))
                    password = self.generate_random_password(length)

                print(colored(f"[+] Generated Password: {password}", "green"))
                break
            except ValueError as e:
                print(colored(f"[-] an error occured: {e}", "red"))

    def generate_combined_password(self, length, phrase):
        """
        Generate a password combining random characters and a user-provided phrase.
        """
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
        """
        Generate a password combining multiple user-provided phrases with random placement.
        """
        transformed_phrases = [''.join([random.choice(self.replacements.get(char.lower(), [char])) for char in phrase]) for phrase in phrases]

        random.shuffle(transformed_phrases)
        password = ''.join(transformed_phrases)
        return password

    def generate_random_password(self, length):
        """
        Generate a random password of the specified length.
        """
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def generate_password_from_phrase(self, phrase):
        """
        Generate a strong password based on a user-provided phrase.
        """
        transformed_phrase = ''.join([random.choice(self.replacements.get(char.lower(), [char])) for char in phrase])
        password = ''.join([random.choice([char.upper(), char.lower()]) for char in transformed_phrase])
        return password

    def generate_pattern_password(self, pattern):
        """
        Generate a password based on a user-defined pattern.
        """
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
        """
        Enables Two-Factor Authentication (2FA) for a user. It reads user data from the USER_DATA_FILE, checks if 2FA is already enabled, generates a random base32-encoded secret key for TOTP, hashes it, updates user_data, and saves it. Finally, it prints a success message with the account name, key, and issuer name.
        """
        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        if user_data.get('2fa_enabled', False):
            print(colored("[-] 2FA is already enabled for this user.", "red"))
            return

        self.totp_secret_key = random_base32()
        key = self.encrypt_information(self.totp_secret_key)
        user_data['2fa_enabled'] = True
        user_data['key'] = key

        with open(self.USER_DATA_FILE, 'w') as file:
            json.dump(user_data, file)

        totp = TOTP(self.totp_secret_key)
        print(colored(f"[+] 2FA Enabled. Now use the account name and the kwy to get the 6 digit code.\nAccount Name - {user_data.get('username', 'Unknown')}\nKey - {self.totp_secret_key}\nIssuer Name - MIRA (CyberGuard Innovations)", "green"))        
        print(colored("\n[*] Keep your Key secure all the time, it will be asked before you enter the 6-digit code for verification! Please handle your keys with care. It's not our fault if you lose it.", "yellow"))

    def verify_2fa(self, secret_key, code):
        """
        Verifies a Two-Factor Authentication (2FA) code for a given secret key. It uses the TOTP class to generate a TOTP instance based on the provided secret_key and then verifies the input code against the generated code. Returns True if the verification is successful.
        """
        totp = TOTP(secret_key)
        return totp.verify(code)

    def notify_expiry_background(self):
        """
        Runs in the background to periodically notify about password expiry. It continuously calls self.notify_expiry() in a loop, catching FileNotFoundError and sleeping for 86400 seconds (24 hours).
"""
        while True:
            try:
                self.notify_expiry()
            except FileNotFoundError:
                pass
            time.sleep(86400)

    def notify_expiry(self):
        """
        Checks the expiry status of passwords in the PASSFILE. If passwords are close to expiry (within 1-7 days), it prints a warning. If expiring within 1 day, it issues an alert. If expired, it indicates a mandatory update for accessibility. Handles FileNotFoundError gracefully.
"""
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

    def notify_pin_expiry_background(self):
        """
        Same as the notify_expiry_background() function but for PIN.
        """
        while True:
            try:
                self.notify_pin_expiry()
            except FileNotFoundError:
                pass
            time.sleep(86400)

    def notify_pin_expiry(self):
        """
        Same as the notify_expiry() function but for PIN again.
        """
        try:
            with open(self.CARD_PIN_FILE, 'r') as file:
                data = json.load(file)

            for entry in data:
                if 'expiry_at' in entry and entry['expiry_at']:
                    expiry_date = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S")
                    time_left = expiry_date - datetime.now()

                    if timedelta(days=1) <= time_left <= timedelta(days=7):
                        days_left = time_left.days
                        hours, remainder = divmod(time_left.seconds, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        print(colored(f"[!] Warning: Some of your PINs will expire in {days_left} days, {hours} hours, {minutes} minutes, and {seconds} seconds. Please update them!", 'yellow'))

                    elif time_left < timedelta(days=1) and time_left >= timedelta(seconds=0):
                        print(colored(f"[!] Alert: Some of your PINs will expire in any minute! Please update them!", 'red'))
                    elif time_left <= timedelta(seconds=0):
                        print(colored(f"[!] Alert: Some of your PINs has expired. Update is now mandatory for accessibility!", 'red'))

        except FileNotFoundError:
            pass

    def load_encryption_key(self, encryption_key):
        self.cipher = self.initialize_cipher(encryption_key)

    def initialize_cipher(self, key):
        return Fernet(key)

    def check_master_password_strength(self, password):
        """
        Checks the strength of the provided master password against MIRA's password policy. If the password doesn't meet the criteria, it prompts the user for generating a strong password or aborts the process.
        """
        policy = PasswordPolicy.from_names(
            length=20,
            uppercase=3,
            numbers=3,
            special=4,
        )
        result = policy.test(password)
        if result:
            print(colored("[-] Master password is not strong enough (Not Added). Please follow our password policy for master password:", "red"))
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

    def check_password_strength(self, password):
        """
        Same as the check_master_password_strength() function but for PINs.
        """
        policy = PasswordPolicy.from_names(
            length=10,
            uppercase=1,
            numbers=1,
            special=1,
        )
        result = policy.test(password)
        
        if result:
            print(colored("[-] Password is not strong enough:", "red"))
            for violation in result:
                print(colored(f"    {violation}", "red"))

            user_choice = input(colored("[*] Do you want to use this password anyway? (y/N): ", "yellow"))

            if user_choice.lower() == 'y':
                return True
            else:
                generate_strong_pass = input(colored("[*] Do you want Mira to generate a strong password for you? (y/N): ", "yellow"))
                if generate_strong_pass.lower() == 'y':
                    self.generate_password()
                    print(colored("[*] Now repeat the process and use that password instead.", "magenta"))
                else:
                    print(colored("[-] Abort.", "red"))
                return False
        return True
    
    def register(self, username, master_password):
        """
        Handles user registration by checking master password strength, creating a new user with encrypted data, and saving security information. Prompts for additional security details and prints registration completion with encryption key.
        Hashing Algorithm used:
        - Argon2
        """
        if not self.check_master_password_strength(master_password):
            return

        if os.path.exists(self.USER_DATA_FILE) and os.path.getsize(self.USER_DATA_FILE) != 0:
            print(colored("[-] Master user already exists!!", "red"))
        else:
            self.master_password = master_password
            salt = token_bytes(100)
            salt_hex = salt.hex()
            hashed_master_password = self.ph.hash(master_password + salt_hex)
            encryption_key = Fernet.generate_key()

            ph = argon2.PasswordHasher()
            hashed_encryption_key = ph.hash(encryption_key.decode())

            user_data = {
                'username': username,
                'salt': salt_hex,
                'master_password': hashed_master_password,
                'encryption_key': hashed_encryption_key
            }
            with open(self.USER_DATA_FILE, 'w') as file:
                json.dump(user_data, file)
                clear_terminal()
                print(colored(wolf, "blue"))
                print(colored("\n[+] Registration complete!!", "green"))
                print(colored(f"[+] Encryption key: {encryption_key.decode()}", "green"))
                print(colored("\n[*] Caution: Save your encryption key and store it somewhere safe Mira will never recover your encryption key once you forgot it!!! So please don't be stupid:)", "yellow"))

    def login(self, username, entered_password, encryption_key):
        """
        Handles user login by verifying entered credentials against stored data. Uses Argon2 hashing for master password and encryption key verification. Checks for account lockout and 2FA if enabled. Prints success and proceeds to the main menu upon successful login.
        """
        if not os.path.exists(self.USER_DATA_FILE):
            print(colored("\n[-] You have not registered. Do that first!", "red"))
        else:
            with open(self.USER_DATA_FILE, 'r') as file:
                user_data = json.load(file)

            if self.lockout_time and time.time() < self.lockout_time:
                clear_terminal()
                print(colored(blehhh, "red"))
                print(colored(f"[-] Account locked. WE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(self.lockout_time - time.time())} seconds.", "red"))
                exit()
                return

            try:
                self.ph.verify(user_data['master_password'], entered_password + user_data['salt'])
            except VerifyMismatchError:
                print(colored("[-] Invalid Login credentials. Login failed!", "red"))
                if self.increment_failed_attempts():
                    return  
                else:
                    return

            if username == user_data['username']:
                stored_encryption_key = user_data['encryption_key']

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
                    key = self.decrypt_information(user_data['key'])
                    code = getpass.getpass(colored("[*] 6-Digit Code (2FA): ", "yellow"))
                    if not self.verify_2fa(key, code):
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
                print(colored("[-] Invalid Login credentials. Login failed!", "red"))
                if self.increment_failed_attempts():
                    clear_terminal()
                    return  
                else:
                    return

    def show_ssh_key(self):
        """
        Displays SSH key information based on the specified platform or all platforms. Reads SSH key data from the SSH file, formats and prints the relevant information. Handles FileNotFoundError and prints an error message if no SSH keys are saved.
        """
        try:
            with open(self.SSH, 'r') as file:
                data = json.load(file)

            key_id = input(colored("[*] Key ID: ", "yellow"))
            if key_id.isdigit():
                key_id = int(key_id)
            else:
                pass
            key_status = []

            for entry in data:
                if entry['key_id'] == key_id or (isinstance(key_id, str) and key_id.lower() == 'all'):
                    added_at = datetime.strptime(entry['added_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")

                    key_status.append({
                        'key_id': entry['key_id'],
                        'username': self.decrypt_information(entry['username']),
                        'key_name': self.decrypt_information(entry['key_name']),
                        'added_at': added_at
                    })

            if key_status:
                if key_id == 'all' or not key_id:
                    print(colored("[+] All Available SSH Keys:", "green"))
                    print(colored("\nKey ID".ljust(23) + "Username".ljust(30) + "SSH Key Name".ljust(30) + "Added At", "cyan"))
                    print(colored("----------".ljust(22) + "--------------------".ljust(30) + "--------------------".ljust(30) + "-------------------", "cyan"))
                    for user_status in key_status:
                        print(f"{colored(str(user_status['key_id']).ljust(22), 'cyan')}{colored(str(user_status['username']).ljust(30), 'cyan')}{colored(str(user_status['key_name']).ljust(30), 'cyan')}{colored(str(user_status['added_at']).ljust(25), 'cyan')}")
                else:
                    print(colored(f"[+] Info about this Key ID {key_id}:", "green"))
                    print(colored("\nUsername".ljust(28) + "SSH Key Name".ljust(29) + "Added At", "cyan"))
                    print(colored("--------------------".ljust(27) + "--------------------".ljust(29) + "-------------------", "cyan"))
                    for user_status in key_status:
                        print(f"{colored(str(user_status['username']).ljust(27), 'cyan')}{colored(str(user_status['key_name']).ljust(29), 'cyan')}{colored(str(user_status['added_at']).ljust(25), 'cyan')}")
            else:
                print(colored("[-] No matching entries found for the specified Username.", "red"))

        except FileNotFoundError:
            print(colored("[-] No SSH Key saved. Show SSH Keys failed!", "red"))

    def show_api_key(self):
        """
        Displays API key information based on the specified platform or all platforms. Reads API key data from the API file, formats and prints the relevant information. Handles FileNotFoundError and prints an error message if no API keys are saved.
        """
        try:
            with open(self.API, 'r') as file:
                data = json.load(file)

            acc_id = input(colored("[*] Account ID: ", "yellow"))
            if acc_id.isdigit():
                acc_id = int(acc_id)
            else:
                pass
            key_status = []

            for entry in data:
                if entry['unique_id'] == acc_id or (isinstance(acc_id, str) and acc_id.lower() == 'all'):
                    added_at = datetime.strptime(entry['added_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")

                    key_status.append({
                        'unique_id': entry['unique_id'],
                        'platform': entry['platform'],
                        'username': self.decrypt_information(entry['key_name']),
                        'added_at': added_at
                    })

            if key_status:
                if acc_id == 'all' or not acc_id:
                    print(colored("[+] All Available API Keys:", "green"))
                    print(colored("\nAccount ID".ljust(23) + "Platform".ljust(30) + "API Key Name".ljust(30) + "Added At", "cyan"))
                    print(colored("----------".ljust(22) + "--------------------".ljust(30) + "--------------------".ljust(30) + "-------------------", "cyan"))
                    for user_status in key_status:
                        print(f"{colored(str(user_status['unique_id']).ljust(22), 'cyan')}{colored(str(user_status['platform']).ljust(30), 'cyan')}{colored(str(user_status['username']).ljust(30), 'cyan')}{colored(str(user_status['added_at']).ljust(25), 'cyan')}")
                else:
                    print(colored(f"[+] Info about this Account ID {acc_id}:", "green"))
                    print(colored("\nPlatform".ljust(28) + "API Key Name".ljust(30) + "Added At", "cyan"))
                    print(colored("--------------------".ljust(27) + "--------------------".ljust(30) + "-------------------", "cyan"))
                    for user_status in key_status:
                        print(f"{colored(str(user_status['platform']).ljust(27), 'cyan')}{colored(str(user_status['username']).ljust(30), 'cyan')}{colored(str(user_status['added_at'].ljust(25)), 'cyan')}")
            else:
                print(colored("[-] No matching entries found for the specified Platform.", "red"))

        except FileNotFoundError:
            print(colored("[-] No API Key saved. Show API Key failed!", "red"))
    
    def show_pin_expiry_status(self):
        """
        Displays the expiry status of PINs based on the specified card type or all card types. Reads PIN data from the CARD_PIN_FILE, formats and prints the relevant information including expiry status and remaining time. Handles FileNotFoundError and prints an error message if no PINs are saved.
        """
        try:
            with open(self.CARD_PIN_FILE, 'r') as file:
                data = json.load(file)

            card_id = input(colored("[*] Card ID: ", "yellow"))
            if card_id.isdigit():
                card_id = int(card_id)
            else:
                pass
            card_status = []

            for entry in data:
                if entry['card_id'] == card_id or (isinstance(card_id, str) and card_id.lower() == 'all'):
                    expiry_status, remaining_time = self.check_expiry_status(entry.get('expiry_at'))
                    added_at = datetime.strptime(entry['added_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
                    expiry_at = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")

                    card_status.append({
                        'card_id': entry['card_id'],
                        'card_type': entry['card_type'],
                        'card_number': self.decrypt_information(entry['card_number']),
                        'status': expiry_status,
                        'added_at': added_at,
                        'expiry_at': expiry_at,
                        'remaining_time': remaining_time
                    })

            if card_status:
                if card_id == 'all' or not card_id:
                    print(colored("[+] All Available Card IDs:", "green"))
                    print(colored("\nCard ID".ljust(22) + "Card Type".ljust(21) + "Card Number".ljust(30) + "Status".ljust(16) + "Added At".ljust(25) + "Expiry At".ljust(25) + "Remaining Time", "cyan"))
                    print(colored("----------".ljust(21) + "----------".ljust(21) + "--------------------".ljust(30) + "----------".ljust(16) + "-------------------".ljust(25) + "-------------------".ljust(25) + "------------------------", "cyan"))
                    for user_status in card_status:
                        print(f"{colored(str(user_status['card_id']).ljust(21), 'cyan')}{colored(str(user_status['card_type']).ljust(21), 'cyan')}{colored(str(user_status['card_number']).ljust(30), 'cyan')}{colored(str(user_status['status']).ljust(25), 'cyan')}{colored(str(user_status['added_at']).ljust(25), 'cyan')}{colored(str(user_status['expiry_at']).ljust(25), 'cyan')}{colored(str(user_status['remaining_time']).ljust(30), 'cyan')}")
                else:
                    print(colored(f"[+] Status of this card ID {card_id}:", "green"))
                    print(colored("\nCard Type".ljust(23) + "Card Number".ljust(30) + "Status".ljust(24) + "Added At".ljust(25) + "Expiry At".ljust(25) + "Remaining Time", "cyan"))
                    print(colored("----------".ljust(22) + "--------------------".ljust(30) + "----------".ljust(24) + "-------------------".ljust(25) + "-------------------".ljust(25) + "------------------------", "cyan"))
                    for user_status in card_status:
                        print(f"{colored(str(user_status['card_type']).ljust(22), 'cyan')}{colored(str(user_status['card_number']).ljust(30), 'cyan')}{colored(str(user_status['status']).ljust(33), 'cyan')}{colored(str(user_status['added_at']).ljust(25), 'cyan')}{colored(str(user_status['expiry_at']).ljust(24), 'cyan')} {colored(str(user_status['remaining_time']).ljust(30), 'cyan')}")
            else:
                print(colored("[-] No matching entries found for the specified Card Type.", "red"))

        except FileNotFoundError:
            print(colored("[-] No PIN saved. Show expiry status failed!", "red"))

    def show_passwd_strength(self):
        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)

            acc_id = input(colored("[*] Account ID: ", "yellow"))
            if acc_id.isdigit():
                acc_id = int(acc_id)
            else:
                pass
            passwd_strength = []

            for entry in data:
                if entry['account_id'] == acc_id or (isinstance(acc_id, str) and acc_id.lower() == 'all'):
                    password = self.decrypt_password(entry['password'])
                    strength = self.check_password_strngth(password)

                    passwd_strength.append({
                        'acc_id': entry['account_id'],
                        'website': entry['website'],
                        'username': self.decrypt_information(entry['username']),
                        'strength': strength
                    })

            if passwd_strength:
                if acc_id == 'all' or not acc_id:
                    print(colored("[+] All Available Users:", "green"))
                    print(colored("\nAccount ID".ljust(25) + "Platform".ljust(31) + "Username".ljust(30) + "Strength", "cyan"))
                    print(colored("----------".ljust(24) + "--------------------".ljust(31) + "--------------------".ljust(30) + "----------", "cyan"))
                    for user_status in passwd_strength:
                        print(f"{colored(str(user_status['acc_id']).ljust(24), 'cyan')}{colored(str(user_status['website']).ljust(31), 'cyan')}{colored(str(user_status['username']).ljust(30), 'cyan')}{colored(str(user_status['strength']), 'cyan')}")
                else:
                    print(colored(f"[+] Password Strength of this Account ID {acc_id}:", "green"))
                    print(colored("\nPlatform".ljust(29) + "Username".ljust(31) + "Strength", "cyan"))
                    print(colored("--------------------".ljust(28) + "--------------------".ljust(31) + "----------", "cyan"))
                    
                    for user_status in passwd_strength:
                        print(f"{colored(str(user_status['website']).ljust(28), 'cyan')}{colored(str(user_status['username']).ljust(31), 'cyan')}{str(user_status['strength'])}")
            else:
                print(colored("[-] No matching entries found for the specified Platform.", "red"))

        except FileNotFoundError:
            print(colored("[-] No passwords saved. Show password strength failed!", "red"))

    def check_password_strngth(self, password):
        is_length_valid = len(password) > 10
        has_uppercase = any(char.isupper() for char in password)
        has_lowercase = any(char.islower() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_special_char = any(char.isalnum() == False for char in password)

        conditions_met = [is_length_valid, has_uppercase, has_lowercase, has_digit, has_special_char]
        num_conditions_met = sum(conditions_met)

        if num_conditions_met == 5:
            return colored("Strong", "green")
        elif num_conditions_met >= 3:
            return colored("Moderate", "yellow")
        else:
            return colored("Weak", "red")

    def show_expiry_status(self):
        """
        Displays the expiry status of passwords based on the specified platform URL or all platforms. Reads password data from the PASSFILE, formats and prints the relevant information including expiry status and remaining time. Handles FileNotFoundError and prints an error message if no passwords are saved.
        """
        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)

            acc_id = input(colored("[*] Account ID: ", "yellow"))
            if acc_id.isdigit():
                acc_id = int(acc_id)
            else:
                pass
            usernames_status = []

            for entry in data:
                if entry['account_id'] == acc_id or (isinstance(acc_id, str) and acc_id.lower() == 'all'):
                    expiry_status, remaining_time = self.check_expiry_status(entry.get('expiry_at'))
                    username = self.decrypt_information(entry['username'])
                    added_at = datetime.strptime(entry['added_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
                    expiry_at = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")

                    usernames_status.append({
                        'account_id': entry['account_id'],
                        'website': entry['website'],
                        'username': username,
                        'status': expiry_status,
                        'added_at': added_at,
                        'expiry_at': f"{expiry_at}",
                        'remaining_time': remaining_time
                    })

            if usernames_status:
                if acc_id == 'all' or not acc_id:
                    print(colored("[+] All Available Platforms:", "green"))
                    print(colored("\nAccount ID".ljust(20) + "Platform".ljust(31) + "Username".ljust(30) + "Status".ljust(16) + "Added At".ljust(25) + "Expiry At".ljust(25) + "Remaining Time", "cyan"))
                    print(colored("----------".ljust(19) + "--------------------".ljust(31) + "--------------------".ljust(30) + "----------".ljust(16) + "-------------------".ljust(25) + "-------------------".ljust(25) + "------------------------", "cyan"))

                    for user_status in usernames_status:
                        print(f"{colored(str(user_status['account_id']).ljust(19), 'cyan')}{colored(str(user_status['website']).ljust(31), 'cyan')}{colored(str(user_status['username']).ljust(30), 'cyan')}{str(user_status['status']).ljust(25)}{colored(str(user_status['added_at']).ljust(25), 'cyan')}{colored(str(user_status['expiry_at']).ljust(24), 'cyan')} {colored(str(user_status['remaining_time']).ljust(30), 'cyan')}")
                else:
                    print(colored(f"[+] Status of this Account ID {acc_id}:", "green"))
                    print(colored("\nPlatform".ljust(31) + "Username".ljust(24) + "Status".ljust(24) + "Added At".ljust(25) + "Expiry At".ljust(25) + "Remaining Time", "cyan"))
                    print(colored("--------------------".ljust(30) + "--------------------".ljust(24) + "----------".ljust(24) + "-------------------".ljust(25) + "-------------------".ljust(25) + "------------------------", "cyan"))
                    for user_status in usernames_status:
                        print(f"{colored(user_status['website'].ljust(30), 'cyan')}{colored(user_status['username'].ljust(24), 'cyan')}{user_status['status'].ljust(33)}{colored(user_status['added_at'].ljust(25), 'cyan')}{colored(user_status['expiry_at'].ljust(24), 'cyan')} {colored(user_status['remaining_time'].ljust(30), 'cyan')}")
            else:
                print(colored("[-] No matching entries found for the specified Platform.", "red"))

        except FileNotFoundError:
            print(colored("[-] No passwords saved. Show expiry status failed!", "red"))

    def check_expiry_status(self, expiry_date):
        """
        Checks the expiry status of a given expiry date. Returns a tuple with the expiry status (colored) and the remaining time as a string. Handles different cases like nearly expired, about to expire, expired, and normal expiration scenarios.
        """
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
        """
        Main menu of MIRA with a wide range of commands.
        """
        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)
        while True:
            choice = input(colored(f"{user_data.get('username')}@MIRA ~> ", "blue"))

            if choice == "":
                continue

            elif choice == 'add_platform_passwd':
                website = input(colored("[*] Platform: ", "yellow"))
                if not validators.url(website):
                    print(colored("[-] The Platform you've entered is Invalid! Please make sure that it's in URL form.", "red"))
                    continue
                email_address = input(colored("[*] Email Address: ", "yellow"))
                if not validators.email(email_address):
                    print(colored("[-] The Email you've entered is Invalid!", "red"))
                    continue
                username = input(colored("[*] Username: ", "yellow"))
                password = getpass.getpass(colored("[*] Password: ", "yellow"))
                re_enter = getpass.getpass(colored("[*] Re-Enter Password: ", "yellow"))
                if re_enter != password:
                    print(colored("[-] Password did not match! QUITTING!", "red"))
                else:
                    self.add_password(website, email_address, username, password)
                    self.notify_expiry()
                    self.notify_pin_expiry()

            elif choice == 'get_platform_passwd':
                try:
                    acc_id = int(input(colored("[*] Account ID: ", "yellow")))
                except ValueError:
                    print(colored("[-] Invalid account ID.", "red"))
                    continue
                decrypted_password = self.get_password(acc_id)

                try:
                    with open(self.PASSFILE, 'r') as file:
                        data = json.load(file)

                    if acc_id not in [entry['account_id'] for entry in data]:
                        print(colored(f"[-] This ID {acc_id} doesn't exist", "red"))
        
                    for entry in data:
                        if entry['account_id'] == acc_id and 'expiry_at' in entry and entry['expiry_at']:
                            expiry_date = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S")
                
                            if datetime.now() > expiry_date:
                                response = input(colored("[*] Password has expired. Do you want to update the password or delete the account for this platform? (U/D): ", "yellow")).lower()
                    
                                if response == 'u':
                                    new_password = getpass.getpass(colored("[*] New Password: ", "yellow"))
                                    re_enter = getpass.getpass(colored("[*] Re-Enter New Password: ", "yellow"))

                                    if any(self.decrypt_password(entry['password']) == new_password for entry in data):
                                        print(colored("[-] Password has been used, avoid reusing passwords. QUITTING!!", "red"))
                                        continue

                                    if re_enter != new_password:
                                        print(colored("[-] Password did not match! QUITTING!", "red"))
                                        continue

                                    if self.check_password_reuse(new_password, data):
                                        print(colored("[-] Password has been used on other platforms. Avoid using the same password on other platforms!!", "red"))
                                        continue

                                    if not self.check_password_strength(new_password):
                                        continue

                                    entry['password'] = self.encrypt_password(new_password)
                                    entry['expiry_at'] = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

                                    with open(self.PASSFILE, 'w') as file:
                                        json.dump(data, file, indent=4)

                                    decrypted_password = self.decrypt_password(entry['password'])
                        
                                    if decrypted_password:
                                        """print(colored(f"[+] Platform: {entry.get('website')}\nEmail: {self.decrypt_information(entry['email_address'])}\nUsername: {self.decrypt_information(entry['username'])}\nKey Content: {decrypted_password}", "green"))"""
                                        print(colored(f"[+] Password updated successfully.", "green"))
                                        continue
                                    else:
                                        print(colored("[-] Password has expired. Please update your password.", "red"))
                                    continue

                                elif response == 'd':
                                    caution = input(colored("[*] Caution: Once you remove it, it will be permanently deleted from your system. Are you sure you want to proceed? (y/N): ", "yellow"))
                        
                                    if caution == 'n':
                                        print(colored("[-] Abort.", "red"))
                                        continue
                                    elif caution == 'y':
                                        data = [e for e in data if not (e['account_id'] == acc_id)]
                                        with open(self.PASSFILE, 'w') as file:
                                            json.dump(data, file, indent=4)

                                        print(colored("[-] Website permanently deleted.", "red"))
                                    continue
                            else:
                                if decrypted_password is not None:
                                    print(colored(f"[+] Platform: {entry.get('website')}\n[+] Email: {self.decrypt_information(entry['email_address'])}\n[+] Username: {self.decrypt_information(entry['username'])}\n[+] Key Content: {decrypted_password}", "green"))
                                    self.notify_expiry()                                                                    
                                    self.notify_pin_expiry()
                                else:
                                    print(colored("[-] Password not found! Did you save the password?", "red"))

                except FileNotFoundError:
                    print(colored("[-] No passwords have been saved yet. Retrieve passwords failed!", "red"))

            elif choice == 'chmast':
                self.change_master_password()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'genpasswd':
                self.generate_password()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'del_platform_passwd':
                self.delete_password()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'del_card_pin':
                self.delete_card_pin()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'del_api_key':
                self.delete_key()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'show_api_key':
                self.show_api_key()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'add_ssh_key':
                username = input(colored("[*] Username: ", "yellow"))
                if not username:
                    print(colored("[-] No username provided! QUITTING!", "red"))
                    continue
                key_name = input(colored("[*] Key Name: ", "yellow"))
                if not key_name:
                    print(colored("[-] No key name provided! QUITTING!", "red"))
                    continue

                print(colored("[*] Enter the Private Key (press Ctrl+D on a new line to finish):", "yellow"))
                private_key_lines = []
                try:
                    while True:
                        line = input()
                        private_key_lines.append(line)
                except EOFError:
                    pass

                print(colored("[*] Enter the Public Key (press Ctrl+D on a new line to finish):", "yellow"))
                public_key_lines = []
                try:
                    while True:
                        line = input()
                        public_key_lines.append(line)
                except EOFError:
                    pass

                private_key = '\n'.join(private_key_lines)
                public_key = '\n'.join(public_key_lines)

                is_password_protected = False
                passphrase = None

                try:
                    key = paramiko.RSAKey(file_obj=io.StringIO(private_key))
                    self.add_ssh_key(username, key_name, private_key, public_key)
                    self.notify_expiry()
                    self.notify_pin_expiry()
                except paramiko.ssh_exception.PasswordRequiredException:
                    is_password_protected = True

                    try:
                        if is_password_protected:
                            print(colored("[*] The private key is Password-Protected!", "magenta"))
                            passphrase = getpass.getpass(colored("[*] Private key passphrase: ", "yellow"))
                            re_enter = getpass.getpass(colored("[*] Re-Enter passphrase: ", "yellow"))
                            if re_enter != passphrase:
                                print(colored("[-] Passphrase did not match! QUITTING!", "red"))
                                continue
                            else:
                                key = paramiko.RSAKey(file_obj=io.StringIO(private_key), password=passphrase)
                        else:
                            key = paramiko.RSAKey(file_obj=io.StringIO(private_key))
                    except Exception as e:
                        print(colored(f"[-] Error: {e}", "red"))
                    else:
                        self.add_ssh_key(username, key_name, private_key, public_key, passphrase)
                        self.notify_expiry()
                        self.notify_pin_expiry()

            elif choice == 'get_ssh_key':
                try:
                    key_id = int(input(colored("[*] Key ID: ", "yellow")))
                except ValueError:
                    print(colored("[-] Invalid Key ID!", "red"))
                    continue
                try:
                    with open(self.SSH, 'r') as file:
                        data = json.load(file)
                    
                    for entry in data:
                        if key_id not in [entry['key_id'] for entry in data]:
                            print(colored(f"[-] This Key ID {key_id} is not available in your vault.", "red"))
                        else:
                            print(colored(f"[+] Username: {colored(self.decrypt_information(entry.get('username')), 'green')}", "yellow"))
                            print(colored(f"[+] Key Name: {colored(self.decrypt_information(entry.get('key_name')), 'green')}", "yellow"))
                            private_key_lines = self.get_private_ssh_key(key_id)
                            if private_key_lines is not None:
                                print(colored("[*] Private Key:", "yellow"))
                                formatted_private_key = ''.join(private_key_lines)
                                print(colored(formatted_private_key, "green"))
                            else:
                                print(colored("[-] Private Key not found!", "red"))
        
                            public_key_lines = self.get_public_ssh_key(key_id)
                            if public_key_lines is not None:
                                print(colored("\n[*] Public Key:", "yellow"))
                                formatted_public_key = ''.join(public_key_lines)
                                print(colored(formatted_public_key, "green"))
                            else:
                                print(colored("[-] Public Key not found!", "red"))

                            decrypted_passphrase = self.get_passphrase_private_ssh_key(key_id)
                            if decrypted_passphrase is not None:
                                print(colored(f"\n[+] Passphrase: {colored(decrypted_passphrase, 'green')}", "yellow"))
                            else:
                                print(colored("[-] Passphrase not found!", "red"))
                except FileNotFoundError:
                    print(colored("[-] No SSH Key have been saved. Retrieve SSH Key failed!", "red"))

            elif choice == 'del_ssh_key':
                self.delete_ssh_key()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'ch_platform_passwd':
                try:
                    acc_id = int(input(colored("[*] Account ID: ", "yellow")))
                except ValueError:
                    print(colored("[-] Invalid Account ID", "red"))
                    continue
                self.change_password(acc_id)
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'ch_card_pin':
                try:
                    card_id = int(input(colored("[*] Card ID: ", "yellow")))
                except ValueError:
                    print(colored("[-] Invalid Card ID!", "red"))
                    continue
                self.change_pin(card_id)
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'ch_ssh_key':
                try:
                    key_id = int(input(colored("[*] Username: ", "yellow")))
                except ValueError:
                    print(colored("[-] Invalid Key ID", "red"))
                    continue
                self.change_ssh_key(key_id)
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'enable2fa':
                with open(self.USER_DATA_FILE, 'r') as file:
                    user_data = json.load(file)

                if user_data.get('2fa_enabled', False):
                    print(colored("[-] 2FA is already enabled for this user.", "red"))
                    continue

                verify = input(colored("[*] After this, you will need to provide the 6-digit code before you can successfully logged in to your vault. Are you sure you want to proceed? (y/N): ", "yellow"))
                if verify == 'y':
                    self.enable_2fa()
                    self.notify_expiry()
                    self.notify_pin_expiry()
                else:
                    print(colored("[-] Abort!", "red"))

            elif choice == 'show_passwd_exp':
                self.show_expiry_status()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'show_pin_exp':
                self.show_pin_expiry_status()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'show_ssh_key':
                self.show_ssh_key()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'show_passwd_strength':
                self.show_passwd_strength()
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'reset':
                caution = input(colored("[*] Caution: After attempting to do reset, all of the data including your passwords and your master user in mira will be deleted permanently! Are you sure that you want to proceed? (y/N): ", "yellow"))
                if caution == 'y':
                    master_password = getpass.getpass(colored("Master Password: ", "yellow"))
                    with open(self.USER_DATA_FILE, 'r') as file:
                        user_data = json.load(file)

                    stored_master_password = user_data['master_password']
                    salt = user_data['salt']

                    try:
                        self.ph.verify(stored_master_password, master_password + salt)
                    except VerifyMismatchError:
                        print(colored("\n[-] Incorrect current master password. Reset procedure failed!", "red"))
                        continue

                    if os.path.exists(self.LOCKOUT_FILE):
                        os.remove(self.LOCKOUT_FILE)
                    else:
                        pass
                    if os.path.exists(self.PASSFILE):
                        os.remove(self.PASSFILE)
                    else:
                        pass
                    if os.path.exists(self.CARD_PIN_FILE):
                        os.remove(self.CARD_PIN_FILE)
                    else:
                        pass
                    if os.path.exists(self.API):
                        os.remove(self.API)
                    else:
                        pass
                    if os.path.exists(self.SSH):
                        os.remove(self.SSH)
                    else:
                        pass
                    os.remove(self.USER_DATA_FILE)
                    print(colored("[+] All data has been successfully removed.", "green"))
                    start_again = input(colored("[*] Do you want to start a new account? (y/N): ", "yellow"))
                    if start_again == 'y':
                        username = input(colored("[*] New Username: ", "yellow"))
                        master_password = getpass.getpass(colored("[*] New Master Password: ", "yellow"))
                        re_enter = getpass.getpass(colored("[*] Re-enter Master Password: ", "yellow"))
                        if re_enter != master_password:
                            print(colored("[-] Master Password Did Not Match! QUITTING!", "red"))
                        else:
                            if not self.check_master_password_strength(master_password):
                                return
                            password_manager.register(username, master_password)
                            break
                    else:
                        print(colored("[-] Abort.", "red"))
                        break
                else:
                    print(colored("[-] Abort.", "red"))
                    break

            elif choice == 'add_api_key':
                platform = input(colored("[*] Platform: ", "yellow"))
                if not validators.url(platform):
                    print(colored("[-] The platform you've entered is Invalid! Please make sure that it's in URL form.", "red"))
                    continue
                key_name = input(colored("[*] Key Name: " , "yellow"))
                if not key_name:
                    print(colored("[-] No key name provided! QUITTING!", "red"))
                    continue
                key = getpass.getpass(colored("[*] API Key: ", "yellow"))
                if not key:
                    print(colored("[-] No key provided! QUITTING!", "red"))
                    continue
                self.add_key(platform, username, key)
                self.notify_expiry()
                self.notify_pin_expiry()

            elif choice == 'add_card_pin':
                card_type = input(colored("[*] Card Type: ", "yellow")).lower()
                if card_type != 'debit' and card_type != 'credit':
                    print(colored("[-] Please specify if Debit or Credit.", "red"))
                    continue
                try:
                    card_number = input(colored("[*] Card Number: ", "yellow"))
                    if not card_number:
                        print(colored("[-] No card number provided! QUITTING!", "red"))
                        continue
                    if card_number.isdigit() and len(card_number) == 16:
                        pin = getpass.getpass(colored("[*] Card PIN: ", "yellow"))
                        if not pin:
                            print(colored("[-] No PIN provided! QUITTING!", "red"))
                            continue
                        digits = [char for char in pin if char.isdigit()]
                        num_digits = len(digits)

                        if pin.isdigit() and len(pin) in (4, 6):
                            re_enter = getpass.getpass(colored("[*] Re-Enter Card PIN: ", "yellow"))
                            if not re_enter:
                                print(colored("[-] Re-Enter your PIN! QUITTING!", "red"))
                                continue
                            if re_enter != pin:
                                print(colored("[-] PIN did not match. QUITTING!", "red"))
                                continue
                            self.add_card_pin(card_type, card_number, pin)
                            self.notify_expiry()
                            self.notify_pin_expiry()
                        else:
                            print(colored(f"[-] Typical PIN length ranges from 4 to 6, the length of the PIN that you've has {num_digits} digits.", "red"))
                    else:
                        print(colored("[-] Invalid Account Number! Account Numbers should be 16-digits", "red"))
                except ValueError:
                    print(colored("[-] No Account Number provided. QUTTING!", "red"))
                    continue

            elif choice == 'get_api_key':
                try:
                    acc_id = int(input(colored("[*] Account ID: ", "yellow")))
                except ValueError:
                    print(colored("[-] Invalid Account ID.", "red"))
                    continue
                decrypted_key = self.get_key(acc_id)

                try:
                    with open(self.API, 'r') as file:                                                      
                        data = json.load(file)

                    for entry in data:
                        if decrypted_key is not None:
                            print(colored(f"[+] Platform: {entry.get('platform')}", "green"))
                            print(colored(f"[+] Keyname: {self.decrypt_information(entry.get('key_name'))}", "green"))
                            print(colored(f"[+] API Key: {decrypted_key}", "green"))
                        else:
                            print(colored("[-] API Key not found. QUITTING!", "red"))
                except FileNotFoundError:
                    print(colored("[-] API Key not found. QUITTING!", "red"))
                    continue

            elif choice == 'get_card_pin':
                try:
                    card_id = int(input(colored("[*] Card Type: ", "yellow")))
                except ValueError:
                    print(colored("[-] Invalid Card ID!", "red"))
                    continue
                decrypted_pin = self.get_card_pin(card_id)
                try:
                    with open(self.CARD_PIN_FILE, 'r') as file:
                        data = json.load(file)

                    if card_id not in [entry['card_id'] for entry in data]:
                        print(colored(f"f[-] This card type {card_id} is not available in your vault.", "red"))
                    else:
                        for entry in data:
                            if entry['card_id'] == card_id:
                                expiry_date = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S") if 'expiry_at' in entry else None

                                if expiry_date and datetime.now() > expiry_date:
                                    response = input(colored("[*] Card PIN has expired. Do you want to update the PIN or delete the card details? (U/D): ", "yellow")).lower()
                                    if response == 'u':
                                        new_pin = getpass.getpass(colored("[*] New Card PIN: ", "yellow"))
                                        re_enter = getpass.getpass(colored("[*] Re-Enter New Card PIN: ", "yellow"))

                                        if re_enter != new_pin:
                                            print(colored("[-] PIN did not match. QUITTING!", "red"))
                                            continue

                                        if any(self.decrypt_information(entry['pin']) == new_pin for entry in data):
                                            print(colored("[-] Card PIN has been used, avoid reusing PINs. QUITTING!!", "red"))
                                            continue

                                        entry['pin'] = self.encrypt_information(new_pin)
                                        entry['expiry_at'] = (datetime.now() + timedelta(days=60)).strftime('%Y-%m-%d %H:%M:%S')

                                        with open(self.CARD_PIN_FILE, 'w') as file:
                                            json.dump(data, file, indent=4)

                                        decrypted_pin = self.decrypt_information(entry['pin'])
                                        if decrypted_pin:
                                            print(colored("[+] Card PIN Update Successfully!", "green"))
                                        else:
                                            print(colored("[-] Card PIN update failed.", "red"))
                                        continue

                                    elif response == 'd':
                                        caution = input(colored("[*] Caution: Once you remove it, it will be permanently deleted from your system. Are you sure you want to proceed? (y/N): ", "yellow"))
                                        if caution == 'n':
                                            print(colored("[-] Abort.", "red"))
                                            continue
                                        elif caution == 'y':
                                            data = [e for e in data if not (e['card_id'] == card_id)]
                                            with open(self.CARD_PIN_FILE, 'w') as file:
                                                json.dump(data, file, indent=4)

                                            print(colored("[+] Card details permanently deleted.", "green"))
                                        continue

                                else:
                                    if decrypted_pin is not None:
                                        print(colored(f"[+] Card Type: {entry.get('card_type')}", "green"))
                                        print(colored(f"[+] Card Number: {self.decrypt_information(entry.get('card_number'))}", "green"))
                                        print(colored(f"[+] Card PIN: {decrypted_pin}", "green"))
                                    else:
                                        print(colored("[-] Card PIN not found. QUITTING!", "red"))

                except FileNotFoundError:
                    print(colored("[-] No card details have been saved. ", "red"))

            elif choice == 'ch_api_key':
                try:
                    acc_id = int(input(colored("[*] Account ID: ", "yellow")))
                except ValueError:
                    print(colored("[-] Invalid Account ID!", "red"))
                    continue
                self.change_key(acc_id)

            elif choice == 'mnemonic_enc_key':
                encryption_key = input(colored("[*] Key: ", "yellow"))
                key = base64.b64decode(encryption_key)
                hex_key = key.hex()
                mnemonic = Mnemonic("english")
                mnemonic_phrase = mnemonic.to_mnemonic(bytes.fromhex(hex_key))
                print(colored(f"[+] Mnemonic Phrase: {mnemonic_phrase}", "green"))
                print(colored(f"[*] It's advisable to write this phrases on a paper or memorize it if you can.", "yellow"))
                continue
            elif choice == 'dec_mnemonic':
                mnemonic_phrase = input(colored("[*] Mnemonic Phrase: ", "yellow"))
                mnemonic = Mnemonic("english")
                key_bytes = mnemonic.to_entropy(mnemonic_phrase)
                key_base64 = base64.b64encode(key_bytes).decode()
                print(colored(f"[+] Encryption Key: {key_base64}", "green"))
                continue

            elif choice == 'lout':
                self.logout()
                break

            elif choice == 'h' or choice == 'help':
                print(colored("""[**] Available Commands:
1. Adding Credentials
    'add_platform_passwd' - Add a new password for the desired account ID
    'add_api_key' - Add new API key for the desired account ID
    'add_card_pin' - Add a new PIN for the desired card ID
    'add_ssh_key' - Add a new SSH Key for the the desired key ID
2. Retrieving Credentials
    'get_platform_passwd' - Display the plaintext version of the password for the desired account ID
    'get_api_key' - Display the plaintext version of the key of the desired account ID
    'get_card_pin' - Display the plaintext version of the PIN for the desired card ID
    'get_ssh_key' - Display the plaintext version of the SSH Key for the desired key ID
3. Deleting Credentials
    'del_platform_passwd' - Delete a saved password according to your desired account ID
    'del_api_key' - Delete key according to your desired account ID
    'del_card_pin' - Delete a saved PIN according to your desired card ID
    'del_ssh_key' - Delete a saved SSH Key according to your desired key ID
4. Changing Credentials
    'ch_platform_pass' - Change the password for the desired account ID
    'ch_card_pin' - Change the password for the desired pin ID
    'ch_api_key' - Change the API Key for the desired account ID
    'ch_ssh_key' - Chabge the SSH Key for the desired key ID
5. Security and Configuration
    'enable2fa' - Enable Two-Factor Authentication for added security
    'genpasswd' - Generate a strong password
    'changemaster' - Change the masterkey
6. Listing and Analysis
    'show_passwd_exp' - List all usernames and their status on a specific platform or all
    'show_pin_exp' - List all card numbers and their status on a specific card type or all
    'show_api_key' - List all API Key name and their date when they were added (No Expiry when it comes to API Keys)
    'show_ssh_key' - List all SSH Key name and their date when they were added (No Expiry when it comes to SSH Keys also)
    'show_passwd_strength' - List the strength of the password of a username on a specific platform
7. Securing Encryption Key
    'mnemonic_enc_key' - Convert the encryption key to a mnemonic phrase
    'dec_mnemonic' - Decode a mnemonic phrase to the original encryption key
8. User Actions
    'lout' - Logout
    'exit' - Terminate MIRA
    'reset' - Delete all data, including the user account permanently (Be cautious with this command! It can result in permanent data loss!)

[**] Security Recommendations: 
- Regularly check for password expiration using 'showexp' command.
- Keep your master password and encryption key secure.
- Enable Two-Factor Authentication for an additional layer of security.

[**] Note: Master Password strength policy requires at least 20 characters with uppercase, numbers, and special characters. (Mandatory).
[**] Note: Password strength policy for platforms requires at least 10 characters with uppercase, numbers, and special characters also. (Optional, but we recommend you to follow our password policy.) """, "cyan"))

            elif choice == 'exit':
                print(colored("[*] MIRA Terminated!", "red"))
                exit()

            elif choice == 'clear':
                clear_terminal()

            elif choice == 'about':
                clear_terminal()
                print(colored(wolf, "blue"))
                print(colored(about, "cyan"))

            else:
                print(colored("[-] Invalid Option", "red"))


    def check_username_reuse(self, new_website, new_username, existing_data):
        """
        Checks if a new website and username combination already exists in the existing data. Returns True if the combination is found, indicating reuse, otherwise returns False.
        """
        for entry in existing_data:
            existing_website = entry['website']
            existing_username = self.decrypt_information(entry['username'])
            if existing_website == new_website and existing_username == new_username:
                return True
        return False

    def check_email_reuse(self, new_email, existing_data):
        for entry in existing_data:
            decrypted_email = self.decrypt_information(entry['email_address'])
            if decrypted_email == new_email:
                user_input = input(colored(f"[*] The email '{new_email}' already exists. Do you want to proceed? (y/N): ", "yellow"))
                if user_input.lower() == 'y':
                    return True
                else:
                    return False
        return False

    def check_password_reuse(self, new_password, existing_data):
        """
        Checks if a new passwordi already exists in the existing data. Returns True if the password is found, indicating reuse, otherwise returns False.
        """
        for entry in existing_data:
            decrypted_password = self.decrypt_password(entry['password'])
            if decrypted_password == new_password:
                return True
        return False

    def add_password(self, website, email_address, username, password):
        """
        Adds a new password entry for a given website and username. Checks for valid URL form and whether the username or password has been used before. Encrypts the password, checks its strength, and saves the new entry to the PASSFILE.
        """

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

        for entry in data:
            decrypted_email = self.decrypt_information(entry['email_address'])
            if decrypted_email == email_address:
                user_input = input(colored(f"[*] The email {email_address} already exists. Do you want to proceed? (y/N): ", "yellow")).lower()
                if user_input == 'y':
                    print(colored("[**] It's advisable not to use the same email for another account.", "cyan"))
                    pass
                else:
                    return

        if self.check_username_reuse(website, username, data):
            print(colored(f"[-] The username {username} already exists for this platform!", "red"))
            return

        if self.check_password_reuse(password, data):
            print(colored("[-] Password has been used to other platforms. (Password not added) Avoid using the same password on other platforms!!", "red"))
            return

        salt = token_bytes(16)
        if self.check_password_strength(password):
            unique_id = int(uuid.uuid4().hex[:4],  16)
            encrypted_password = self.encrypt_password(password)
            encrypted_email = self.encrypt_information(email_address)
            encrypted_username = self.encrypt_information(username)
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            password_entry = {
                'account_id': unique_id,
                'website': website,
                'email_address': encrypted_email,
                'username': encrypted_username,
                'password': encrypted_password,
                'added_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'expiry_at': (datetime.strptime(current_time, '%Y-%m-%d %H:%M:%S') + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

            }
            data.append(password_entry)
            with open(self.PASSFILE, 'w') as file:
                json.dump(data, file, indent=4)
            print(colored(f"[+] Password added! Account ID for this account: {unique_id}", "green"))
        else:
            print(colored("[-] Password not added. Please choose a stronger password.", "red"))

    def get_password(self, i_d):
        """
        Retrieves the decrypted password for a given website and username. Checks for the existence of the PASSFILE, loads data, and decrypts the password if the entry matches. Handles JSONDecodeError and expiry date verification. Returns the decrypted password or None if not found or expired.
        """
        if not os.path.exists(self.PASSFILE):
            return None

        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for entry in data:
            if entry['account_id'] == i_d and entry.get('email_address') and entry.get('username'):
                website = entry.get('website')
                decrypted_email = self.decrypt_information(entry['email_address'])
                decrypted_username = self.decrypt_information(entry['username'])
            
                if 'expiry_at' in entry and entry['expiry_at']:
                    expiry_date = datetime.strptime(entry['expiry_at'], "%Y-%m-%d %H:%M:%S")
                    if datetime.now() > expiry_date:
                        return None

                decrypted_password = self.decrypt_password(entry['password'])
                return decrypted_password

        return None

    def delete_password(self):
        """
        Allows the user to delete a password entry for a given platform (website) and username. Prompts for platform URL, username, and current master password for verification. Verifies the master password, loads data from PASSFILE, deletes the matching entry, and updates the file. Handles incorrect master password, non-existent passwords, and deletion failure scenarios.
        """
        try:
            acc_id = int(input(colored("[*] Account ID: ", "yellow")))
        except ValueError:
            print(colored("[-] Invalid Account ID", "red"))
            return

        master_pass = getpass.getpass(colored("[*] Master Password: ", "yellow"))

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
            print(colored("[-] Incorrect current master password. Delete password failed!", "red"))
            return

        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for entry in data:
            if entry['account_id'] == acc_id and entry.get('email_address') and entry.get('username'):
                data.remove(entry)
                with open(self.PASSFILE, 'w') as file:
                    json.dump(data, file, indent=4)
                print(colored("[+] Password deleted successfully!", "green"))
                if not data:
                    os.remove(self.PASSFILE)
                    return

        print(colored("[-] Password not found! Deletion failed!", "red"))

    def change_password(self, acc_id):
        """
        Allows the user to change the password for a given account ID. It prompts for the current password, verifies it, and then prompts for a new password. It encrypts and updates the password entry in the PASSFILE. Handles scenarios like incorrect current password, non-existent passwords, and password strength requirements.
        """
        data = []

        if not os.path.exists(self.PASSFILE):
            print(colored("[-] No passwords saved!", "red"))
            return

        try:
            with open(self.PASSFILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            pass

        current_password = getpass.getpass(colored("[*] Current password for the given account ID: ", "yellow"))

        decrypted_password = self.get_password(acc_id)
    
        if decrypted_password is not None and current_password == decrypted_password:
            new_password = getpass.getpass(colored("[*] New Password: ", "yellow"))
            re_enter = getpass.getpass(colored("[*] Re-Enter New Password: ", "yellow"))

            if not self.check_password_strength(new_password):
                return

            if new_password != re_enter:
                print(colored("[-] New Passwords Did Not Match! Change password failed!", "red"))
                return

            encrypted_new_password = self.encrypt_password(new_password)
    
            if any(self.decrypt_password(entry['password']) == new_password for entry in data):
                print(colored("[-] Password has been used. (Change password failed) Avoid reusing passwords!", "red"))
                return

            try:
                with open(self.PASSFILE, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []

            for entry in data:
                if entry['account_id'] == acc_id:
                    entry['password'] = encrypted_new_password
                    entry['expiry_at'] = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

                    with open(self.PASSFILE, 'w') as file:
                        json.dump(data, file, indent=4)

                    decrypted_password = self.decrypt_password(entry['password'])
                    if decrypted_password:
                        print(colored("[+] Password updated successfully!", "green"))
                    else:
                        print(colored("[-] Password update failed.", "red"))
                    return

        elif acc_id not in [entry['account_id'] for entry in data]:
            print(colored("[-] This account ID is not available in your vault.", "red"))
        else:
            print(colored("[-] Incorrect current password. Change password failed!", "red"))

    def encrypt_password(self, password):
        """
        It takes a password, encodes it, encrypts it using the cipher, and returns the encrypted password as a string.
        """
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """
        It takes a cipher version of the password, encodes it, decrypts it, and returns the decrypted password as a string.
        """
        return self.cipher.decrypt(encrypted_password.encode()).decode()

    def change_master_password(self):
        """
        Prompts the user for the current master password, verifies it, and then allows the user to set a new master password.
        """
        current_password = getpass.getpass(colored("[*] Current Master Password: ", "yellow"))
        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        stored_master_password = user_data['master_password']
        salt = user_data['salt']

        try:
            self.ph.verify(stored_master_password, current_password + salt)
        except VerifyMismatchError:
            print(colored("[-] Incorrect current master password. Change password failed!", "red"))
            return

        new_password = getpass.getpass(colored("[*] New Master Password: ", "yellow"))
        re_enter = getpass.getpass(colored("[*] Re-Enter Master Password: ", "yellow"))

        if not self.check_master_password_strength(new_password):
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

    def check_keyname_reuse(self, new_platform, new_key_name, existing_data):
        """
        Checks if a new API key's platform and key name combo is already in use in existing_data.
        """
        for entry in existing_data:
            existing_platform = entry['platform']
            existing_key_name = self.decrypt_information(entry['key_name'])
            if existing_platform == new_platform and existing_key_name == new_key_name:
                return True
        return False

    def check_key_reuse(self, new_key, existing_data):
        """
        Checks if a new API key is already in use in existing_data.
        """
        for entry in existing_data:
            decrypted_key = self.decrypt_information(entry['key'])
            if decrypted_key == new_key:
                return True
        return False

    def add_key(self, platform, key_name, key):
        """
        Adds a new API key entry with the specified platform, key name, and key to the API file.
        """
        if not os.path.exists(self.API):
            data = []
        else:
            try:
                with open(self.API, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []
            except FileNotFoundError:
                pass

        if self.check_keyname_reuse(platform, key_name, data):
            print(colored(f"[-] The key name {key_name} already exists for this Platform!", "red"))
            return

        if self.check_key_reuse(key, data):
            print(colored("[-] API Key has been used to other Key Name. (API Key not added) Avoid using the same API on other Key Name!!", "red"))
            return

        unique_id = int(uuid.uuid4().hex[:4],  16)

        api_key_entry = {
            'unique_id': unique_id,
            'platform': platform,
            'key_name': self.encrypt_information(key_name),
            'key': self.encrypt_information(key),
            'added_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        data.append(api_key_entry)
        with open(self.API, 'w') as file:
            json.dump(data, file, indent=4)

        print(colored(f"[+] API Key added! Account ID for this API Key: {unique_id}.", "green"))

    def check_cardnumber_reuse(self, new_card_type, new_card_number, existing_data):
        """
        Checks if the new card type and number combo already exists in the existing data.
        """
        for entry in existing_data:
            existing_card_type = entry['card_type']
            existing_card_number = self.decrypt_information(entry['card_number'])
            if existing_card_type == new_card_type and existing_card_number == new_card_number:
                return True
        return False

    def check_pin_reuse(self, new_pin, existing_data):
        """
        Checks if the new PIN is used in other entries.
        """ 
        for entry in existing_data:
            decrypted_pin = self.decrypt_information(entry['pin'])
            if decrypted_pin == new_pin:
                return True
        return False

    def add_card_pin(self, card_type, card_number, pin):
        if not os.path.exists(self.CARD_PIN_FILE):
            data = []
        else:
            try:
                with open(self.CARD_PIN_FILE, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []
            except FileNotFoundError:
                pass

        if self.check_cardnumber_reuse(card_type, card_number, data):
            print(colored(f"[-] The card number {card_number} already exists for this card type!", "red"))
            return

        if self.check_pin_reuse(pin, data):
            print(colored("[-] PIN has been used to other card number. (PIN not added) Avoid using the same PIN on other card numbers!!", "red"))
            return

        unique_id = int(uuid.uuid4().hex[:4],  16)

        card_pin_entry = {
            'card_id': unique_id,
            'card_type': card_type,
            'card_number': self.encrypt_information(card_number),
            'pin': self.encrypt_information(pin),
            'added_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'expiry_at': (datetime.now() + timedelta(days=60)).strftime('%Y-%m-%d %H:%M:%S')
        }

        data.append(card_pin_entry)
        with open(self.CARD_PIN_FILE, 'w') as file:
            json.dump(data, file, indent=4)

        print(colored(f"[+] Card PIN added! Card ID for this PIN: {unique_id}.", "green"))

    def get_key(self, acc_id):
        if not os.path.exists(self.API):
            return None

        try:
            with open(self.API, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            return None

        for entry in data:
            if entry['unique_id'] == acc_id:
                decrypted_key_name = self.decrypt_information(entry['key_name'])
                decrypted_key = self.decrypt_information(entry['key'])
                return decrypted_key

        return None

    def get_card_pin(self, card_id):
        if not os.path.exists(self.CARD_PIN_FILE):
            return None

        try:
            with open(self.CARD_PIN_FILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            return None

        for entry in data:
            if entry['card_id'] == card_id:
                decrypted_pin = self.decrypt_information(entry['pin'])
                return decrypted_pin

        return None

    def delete_card_pin(self):
        try:
            card_id = int(input(colored("[*] Card ID: ", "yellow")))
        except ValueError:
            print(colored("[-] Invalid Card ID!", "red"))
            return
        master_pass = getpass.getpass(colored("[*] Master Password: ", "yellow"))
        if not os.path.exists(self.CARD_PIN_FILE):
            print(colored("[-] No PIN saved. Deletion failed!", "red"))
            return

        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        stored_master_password = user_data['master_password']
        salt = user_data['salt']

        try:
            self.ph.verify(stored_master_password, master_pass + salt)
        except VerifyMismatchError:
            print(colored("[-] Incorrect current master password. Deletion failed!", "red"))
            return

        try:
            with open(self.CARD_PIN_FILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for entry in data:
            if entry['card_id'] == card_id:
                data.remove(entry)
                with open(self.CARD_PIN_FILE, 'w') as file:
                    json.dump(data, file, indent=4)
                print(colored("[+] Card PIN deleted successfully!", "green"))
                if not data:
                    os.remove(self.CARD_PIN_FILE)
                    return

        print(colored("[-] PIN not found! Deletion failed!", "red"))

    def delete_key(self):
        try:
            acc_id = int(input(colored("[*] Account ID: ", "yellow")))
        except ValueError:
            print(colored("[-] Invalid Account ID!", "red"))
            return
        master_pass = getpass.getpass(colored("[*] Master Password: ", "yellow"))

        if not os.path.exists(self.API):
            print(colored("[-] No API Keys saved. Deletion failed", "red"))
            return

        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        stored_master_password = user_data['master_password']
        salt = user_data['salt']

        try:
            self.ph.verify(stored_master_password, master_pass + salt)
        except VerifyMismatchError:
            print(colored("[-] Incorrect current master password. Deletion failed!", "red"))
            return

        try:
            with open(self.API, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for entry in data:
            if entry['unique_id'] == acc_id:
                data.remove(entry)
                with open(self.API, 'w') as file:
                    json.dump(data, file, indent=4)
                print(colored("[+] API Key successfully deleted!", "green"))
                if not data:
                    os.remove(self.API)
                    return

        print(colored("[-] API Key not found! Deletion failed!", "red"))

    def change_pin(self, card_id):
        data = []

        if not os.path.exists(self.CARD_PIN_FILE):
            print(colored("[-] No PIN saved!", "red"))
            return

        try:
            with open(self.CARD_PIN_FILE, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            pass

        for entry in data:
            current_pin = getpass.getpass(colored(f"[*] Current PIN for the given card ID (No: {self.decrypt_information(entry.get('card_number'))}): ", "yellow"))

        decrypted_pin = self.get_card_pin(card_id)

        if decrypted_pin is not None and current_pin == decrypted_pin:
            try:
                new_pin = getpass.getpass(colored("[*] New PIN: ", "yellow"))
                digits = [char for char in new_pin if char.isdigit()]
                num_digits = len(digits)
                if new_pin.isdigit() and len(new_pin) not in (4, 6):
                    print(colored(f"[-] Typical length of PINs are ranges from 4 to 6 digits! The PIN you've entered has {num_digits} digits.", "red"))
                    return
                if not new_pin:
                    print(colored("[-] No PIN provided! Changing process failed.", "red"))
                    return
                new_pin_input = int(new_pin)
                re_enter = getpass.getpass(colored("[*] Re-Enter New PIN: ", "yellow"))
                if not re_enter:
                    print(colored("[-] Please Re-Enter your new PIN! QUITTING!", "red"))
                    return
                re_enter_input = int(re_enter)
            except ValueError:
                print(colored("[-] Please provide a PIN", "red"))
                return
                
            if new_pin_input != re_enter_input:
                print(colored("[-] New PINs Did Not Match! Change PIN failed!", "red"))
                return

            encrypted_new_pin = self.encrypt_information(new_pin)
        
            if any(self.decrypt_information(entry['pin']) == new_pin for entry in data):
                print(colored("[-] PIN has been used. (Change PIN failed) Avoid reusing PINs!", "red"))
                return

            try:
                with open(self.CARD_PIN_FILE, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []

            for entry in data:
                if entry['card_id'] == card_id:
                    entry['pin'] = encrypted_new_pin
                    entry['expiry_at'] = (datetime.now() + timedelta(days=60)).strftime('%Y-%m-%d %H:%M:%S')

                    with open(self.CARD_PIN_FILE, 'w') as file:
                        json.dump(data, file, indent=4)

                    decrypted_pin = self.decrypt_information(entry['pin'])
                    if decrypted_pin:
                        print(colored("[+] PIN updated successfully!", "green"))
                    else:
                        print(colored("[-] PIN update failed.", "red"))
                    return

        elif card_id not in [entry['card_id'] for entry in data]:
            print(colored(f"[-] This Card ID {card_id} is not available on your PIN vault.", "red"))
        else:
            print(colored("[-] Incorrect current PIN. Change PIN failed!", "red"))

    def change_key(self, acc_id):
        data = []

        if not os.path.exists(self.API):
            print(colored("[-] No KEYS saved!", "red"))
            return

        try:
            with open(self.API, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            pass


        current_key = getpass.getpass(colored("[*] Current API key for the given Account ID: ", "yellow"))

        decrypted_key = self.get_key(acc_id)

        if decrypted_key is not None and current_key == decrypted_key:
            new_key = getpass.getpass(colored("[*] New API Key: ", "yellow"))
            re_enter = getpass.getpass(colored("[*] Re-Enter New API Key: ", "yellow"))

            if new_key != re_enter:
                print(colored("[-] New API Key Did Not Match! Change Key failed!", "red"))
                return

            encrypted_new_key = self.encrypt_information(new_key)

            if any(self.decrypt_information(entry['key']) == new_key for entry in data):
                print(colored("[-] API Key has been used. (Change Key failed) Avoid reusing Keys!", "red"))
                return

            try:
                with open(self.API, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []

            for entry in data:
                if entry['unique_id'] == acc_id:
                    entry['key'] = encrypted_new_key

                    with open(self.API, 'w') as file:
                        json.dump(data, file, indent=4)

                    decrypted_key = self.decrypt_information(entry['key'])
                    if decrypted_key:
                        print(colored("[+] API Key updated successfully!", "green"))
                    else:
                        print(colored("[-] API Key update failed.", "red"))
                    return

        elif acc_id not in [entry['unique_id'] for entry in data]:
            print(colored("[-] This Account ID is not available on your vault.", "red"))
        else:
            print(colored("[-] Incorrect current API Key. Change Key failed!", "red"))

    def check_ssh_keyname_reuse(self, new_username, new_key_name, existing_data):
        """
        Checks if a new SSH key's platform and key name combo is already in use in existing_data.
        """                                                                                                                   
        for entry in existing_data:
            existing_username = entry['username']
            existing_key_name = entry['key_name']
            if existing_username == new_username and existing_key_name == new_key_name:
                return True
        return False

    def check_ssh_key_reuse(self, public_key, private_key, existing_data):
        """
        Checks if a new SSH key is already in use in existing_data.
        """
        for entry in existing_data:
            decrypted_pub_key = self.decrypt_information(entry['public_key'])
            decrypted_priv_key = self.decrypt_information(entry['private_key'])
            if decrypted_pub_key == public_key and decrypted_priv_key == private_key:
                return True                                                                                          

        return False

    def is_valid_ssh_private_key(self, private_key):
        if not private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
            return False

    def is_valid_ssh_public_key(self, public_key):
        if not public_key.startswith("ssh-rsa"):
            return False

    def add_ssh_key(self, username, key_name, private_key, public_key, passphrase=None):
        """
        Adds a new SSH key entry with the specified username, key name, and key to the SSH file.
        """
        if not os.path.exists(self.SSH):
            data = []
        else:
            try:
                with open(self.SSH, 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                data = []
            except FileNotFoundError:
                pass

        if self.check_ssh_keyname_reuse(username, key_name, data):
            print(colored(f"[-] The key name {key_name} already exists for this username!", "red"))
            return

        if self.check_ssh_key_reuse(public_key, private_key, data):
            print(colored("[-] The key has been used to other Key Name. (Both Key not added) Avoid using the same Key on other Key Name!!", "red"))
            return

        unique_id = int(uuid.uuid4().hex[:4],  16)

        ssh_key_entry = {
            'key_id': unique_id,
            'username': self.encrypt_information(username),
            'key_name': self.encrypt_information(key_name),
            'public_key': self.encrypt_information(public_key),
            'private_key': self.encrypt_information(private_key),
            'passphrase': self.encrypt_information(passphrase) if passphrase else 'null',
            'added_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        data.append(ssh_key_entry)
        with open(self.SSH, 'w') as file:
            json.dump(data, file, indent=4)

        print(colored(f"[+] SSH Key added! Key ID for that Key: {unique_id}", "green"))

    def get_private_ssh_key(self, key_id):
        if not os.path.exists(self.SSH):
            return None

        try:
            with open(self.SSH, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            return None

        for entry in data:
            if entry['key_id'] == key_id:
                decrypted_priv_key = self.decrypt_information(entry['private_key'])
                return decrypted_priv_key

        return None

    def get_public_ssh_key(self, key_id):
        if not os.path.exists(self.SSH):
            return None

        try:
            with open(self.SSH, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            return None

        for entry in data:
            if entry['key_id'] == key_id:
                decrypted_pub_key = self.decrypt_information(entry['public_key'])
                return decrypted_pub_key

        return None

    def get_passphrase_private_ssh_key(self, key_id):
        if not os.path.exists(self.SSH):
            return None

        try:
            with open(self.SSH, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            return None

        for entry in data:
            if entry['key_id'] == key_id:
                encrypted_passphrase = entry['passphrase']
                if encrypted_passphrase.lower() == 'null':
                    return colored("null", "red")
                else:
                    passphrase = self.decrypt_information(encrypted_passphrase)
                    return passphrase.lower() if passphrase else None

        return None

    def delete_ssh_key(self):
        try:
            key_id = int(input(colored("[*] Key ID: ", "yellow")))
        except ValueError:
            print(colored("[-] Invalid Key ID!", "red"))
            return
        master_pass = getpass.getpass(colored("[*] Master Password: ", "yellow"))

        if not os.path.exists(self.SSH):
            print(colored("[-] No SSH Keys saved. Deletion failed", "red"))
            return

        with open(self.USER_DATA_FILE, 'r') as file:
            user_data = json.load(file)

        stored_master_password = user_data['master_password']
        salt = user_data['salt']

        try:
            self.ph.verify(stored_master_password, master_pass + salt)
        except VerifyMismatchError:
            print(colored("[-] Incorrect current master password. Deletion failed!", "red"))
            return

        try:
            with open(self.SSH, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []
                                                                                                
        for entry in data:                                                                          
            if entry['key_id'] == key_id:
                data.remove(entry)
                with open(self.SSH, 'w') as file:
                    json.dump(data, file, indent=4)
                print(colored("[+] SSH Key successfully deleted!", "green"))
                if not data:
                    os.remove(self.SSH)
                    return

        print(colored("[-] SSH Key not found! Deletion failed!", "red"))

    def change_ssh_key(self, key_id):
        data = []
    
        if not os.path.exists(self.SSH):
            print(colored("[-] No SSH Keys saved!", "red"))
            return

        try:
            with open(self.SSH, 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            pass

        for entry in data:
            if key_id not in [entry['key_id'] for entry in data]:
                print(colored(f"[-] This username {key_id} is not available on your SSH Key vault.", "red"))
                return

        # Ask for passphrase verification if it's not 'null'
        for entry in data:
            if entry['passphrase'] == 'null':
                pass
            else:
                current_passphrase = getpass.getpass(colored("[*] Current Passphrase for verification: ", "yellow"))
                decrypted_passphrase = self.decrypt_information(entry['passphrase'])
                if current_passphrase != decrypted_passphrase:
                    print(colored("[-] Incorrect current passphrase!", "red"))
                    return

        try:
            print(colored("[*] Enter the New Private Key (press Ctrl+D on a new line to finish):", "yellow"))
            new_private_key_lines = []
            try:
                while True:
                    line = input()
                    new_private_key_lines.append(line)
            except EOFError:
                pass

            print(colored("[*] Enter the New Public Key (press Ctrl+D on a new line to finish):", "yellow"))
            new_public_key_lines = []
            try:
                while True:
                    line = input()
                    new_public_key_lines.append(line)
            except EOFError:
                pass
        except paramiko.ssh_exception.SSHException:
            print(colored("[-] Invalid OpenSSH private key", "red"))
            return

        new_private_key = '\n'.join(new_private_key_lines)
        new_public_key = '\n'.join(new_public_key_lines)

        if not new_private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
            print(colored("[-] Invalid SSH Private Key!", "red"))
            return

        if not new_public_key.startswith("ssh-rsa"):
            print(colored("[-] Invalid SSH Public Key!", "red"))
            return

        is_password_protected = False
        passphrase = None

        try:
            new_key = paramiko.RSAKey(file_obj=io.StringIO(new_private_key))
            for entry in data:
                if entry['key_id'] == key_id:
                    entry['private_key'] = self.encrypt_information(new_private_key)
                    entry['public_key'] = self.encrypt_information(new_public_key)
                    entry['passphrase'] = 'null'

            with open(self.SSH, 'w') as file:
                json.dump(data, file, indent=4)

            print(colored("[+] SSH Key updated successfully!", "green"))
        except paramiko.ssh_exception.PasswordRequiredException:
            is_password_protected = True

            try:
                if is_password_protected:
                    print(colored("[*] The new private key is Password-Protected!", "magenta"))
                    new_passphrase = getpass.getpass(colored("[*] Enter the new private key passphrase: ", "yellow"))
                    re_enter = getpass.getpass(colored("[*] Re-Enter new private key passphrase: ", "yellow"))
                    if re_enter != new_passphrase:
                        print(colored("[-] New Password did not match. QUITTING!"))
                        return
                    new_key = paramiko.RSAKey(file_obj=io.StringIO(new_private_key), password=new_passphrase)
                else:
                    new_key = paramiko.RSAKey(file_obj=io.StringIO(new_private_key))
            except Exception as e:
                print(colored(f"[-] Error: {e}", "red"))
            except paramiko.ssh_exception.SSHException:                                                              
                print(colored("[-] Error: Invalid Private Key!", "red"))
            else:
                for entry in data:
                    if entry['key_id'] == key_id:
                            
                        entry['private_key'] = self.encrypt_information(new_private_key)
                        entry['public_key'] = self.encrypt_information(new_public_key)
                        entry['passphrase'] = self.encrypt_information(new_passphrase)

                with open(self.SSH, 'w') as file:
                    json.dump(data, file, indent=4)

                print(colored("[+] SSH Key updated successfully!", "green"))
        
    def encrypt_information(self, information):
        return self.cipher.encrypt(information.encode()).decode()

    def decrypt_information(self, encrypted_information):
        return self.cipher.decrypt(encrypted_information.encode()).decode()

    def logout(self):
        self.master_password = None
        self.cipher = None
        print(colored("[+] Logged out!", "cyan"))

if __name__ == '__main__':
    if platform.system() == 'Linux':
        if not check_linux_privileges():
            print(colored("[-] Mira requires elevated privileges on Linux. QUITTING!", "red"))
            exit()
        else:
            try:
                clear_terminal()
                current_datetime_info = get_current_datetime()
                os_distribution_info = get_os_distribution()                                                                          
                print(colored(os_distribution_info, "blue"))
                time.sleep(2)
                print(colored(get_python_version(), "blue"))
                time.sleep(2)                                                                                                         
                print(colored(current_datetime_info, "blue"))                                                                         
                time.sleep(2)
                print(colored("[+] Starting Mira Password Manager.....", "blue"))
                password_manager = PasswordManager()
                #time.sleep(20)
                if password_manager.lockout_time and time.time() < password_manager.lockout_time:                                         
                    clear_terminal()
                    print(colored(blehhh, "red"))
                    print(colored(f"[-] Account locked. WE'VE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(password_manager.lockout_time - time.time())} seconds.", "red"))                           
                    exit()                                                                                                            
                clear_terminal()
                print(colored(wolf, "blue"))
                while True:
                    choice = input(colored("MIRA> ", "blue"))

                    if choice == "":
                        continue

                    elif choice == 'regis':
                        if os.path.exists(password_manager.USER_DATA_FILE) and os.path.getsize(password_manager.USER_DATA_FILE) != 0:
                            print(colored("[-] Master user already exists!!", "red"))                                                         
                        else:
                            username = input(colored("[*] New Username: ", "yellow"))
                            master_password = getpass.getpass(colored("[*] New Master Password: ", "yellow"))                                     
                            re_enter = getpass.getpass(colored("[*] Re-Enter Master Password: ", "yellow"))                                       
                            if re_enter != master_password:
                                print(colored("[-] Master Password Did Not Match! QUITTING!", "red"))
                            else:
                                password_manager.register(username, master_password)

                    elif choice == 'log':
                        if password_manager.lockout_time and time.time() < password_manager.lockout_time:
                            clear_terminal()
                            print(colored(blehhh, "red"))
                            print(colored(f"[-] Account locked. WE'VE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(password_manager.lockout_time - time.time())} seconds.", "red"))
                            exit()
                        if os.path.exists(password_manager.USER_DATA_FILE):
                            username = input(colored("[*] Username: ", "yellow"))
                            master_password = getpass.getpass(colored("[*] Master password: ", "yellow"))
                            encryption_key = getpass.getpass(colored("[*] Encryption key: ", "yellow"))
                            password_manager.login(username, master_password, encryption_key)
                        else:
                            print(colored("[-] You have not registered. Please do that.", "red"))

                    elif choice == 'help' or choice == 'h':
                        if password_manager.lockout_time and time.time() < password_manager.lockout_time:
                            clear_terminal()
                            print(colored(blehhh, "red"))
                            print(colored(f"[-] Account locked. WE'VE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(password_manager.lockout_time - time.time())} seconds.", "red"))
                            exit()
                        print(colored(""""[**] Available Commands:
'log' - Login (Mske sure you're registered before attempt to login)
'regis' - Register for new user (Only one user!)
'quit' - Terminate MIRA
'about' - More information about MIRA
'h' - Help""", "cyan"))

                    elif choice == 'dec_mnemonic':                                                                                                                   
                        if password_manager.lockout_time and time.time() < password_manager.lockout_time:
                            clear_terminal()
                            print(colored(blehhh, "red"))                                                                                                                
                            print(colored(f"[-] Account locked. WE'VE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(password_manager.lockout_time - time.time())} seconds.", "red"))
                            exit()
                        mnemonic_phrase = input(colored("[*] Mnemonic Phrase: ", "yellow"))
                        mnemonic = Mnemonic("english")
                        key_bytes = mnemonic.to_entropy(mnemonic_phrase)
                        key_base64 = base64.b64encode(key_bytes).decode()                                                                                            
                        print(colored(f"[+] Encryption Key: {key_base64}", "green"))

                    elif choice == 'quit':
                        print(colored("\n[-] Exiting Mira.....", "red"))
                        time.sleep(3)
                        clear_terminal()
                        print(colored(remember, "cyan"))
                        print(colored("Creating a password is like crafting a witty joke: it should be unique, memorable, and leave hackers scratching their heads. So, don't be shy to sprinkle a dash of humor into your password game – after all, laughter is the best encryption!", "cyan"))
                        exit()

                    elif choice == 'about':
                        clear_terminal()
                        print(colored(wolf, "cyan"))
                        print(colored(about, "cyan"))

                    elif choice == 'clear':
                        clear_terminal()
                    else:
                        print(colored("[-] Invalid Option", "red"))

            except KeyboardInterrupt:
                print(colored("\n[-] Exiting Mira.....", "red"))
                time.sleep(3)
                clear_terminal()
                print(colored(remember, "cyan"))
                print(colored("Creating a password is like crafting a witty joke: it should be unique, memorable, and leave hackers scratching their heads. So, don't be shy to sprinkle a dash of humor into your password game – after all, laughter is the best encryption!", "cyan"))
                exit()

    elif platform.system() == 'Windows':
        if not check_windows_privileges():
            print(colored("[-] Mira requires elevated privileges on Windows. QUITTING!", "red"))
            exit()
        else:
            try:
                clear_terminal()
                current_datetime_info = get_current_datetime()
                os_distribution_info = get_os_distribution()
                print(colored(os_distribution_info, "blue"))
                time.sleep(2)
                print(colored(get_python_version(), "blue"))
                time.sleep(2)
                print(colored(current_datetime_info, "blue"))
                time.sleep(2)
                print(colored("[+] Starting Mira Password Manager.....", "blue"))
                password_manager = PasswordManager()
                time.sleep(20)
                if password_manager.lockout_time and time.time() < password_manager.lockout_time:
                    clear_terminal()
                    print(colored(blehhh, "red"))
                    print(colored(f"[-] Account locked. WE'VE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(password_manager.lockout_time - time.time())} seconds.", "red"))
                    exit()
                clear_terminal()
                print(colored(wolf, "blue"))
                while True:
                    choice = input(colored("MIRA> ", "blue"))
    
                    if choice == "":
                        continue

                    elif choice == 'regis':
                        if os.path.exists(password_manager.USER_DATA_FILE) and os.path.getsize(password_manager.USER_DATA_FILE) != 0:
                            print(colored("[-] Master user already exists!!", "red"))
                        else:
                            username = input(colored("[*] New Username: ", "yellow"))
                            master_password = getpass.getpass(colored("[*] New Master Password: ", "yellow"))
                            re_enter = getpass.getpass(colored("[*] Re-Enter Master Password: ", "yellow"))
                            if re_enter != master_password:
                                print(colored("[-] Master Password Did Not Match! QUITTING!", "red"))
                            else:
                                password_manager.register(username, master_password)

                    elif choice == 'log':
                        if password_manager.lockout_time and time.time() < password_manager.lockout_time:
                            clear_terminal()
                            print(colored(blehhh, "red"))
                            print(colored(f"[-] Account locked. WE'VE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(password_manager.lockout_time - time.time())} seconds.", "red"))
                            exit()
                        if os.path.exists(password_manager.USER_DATA_FILE):
                            username = input(colored("[*] Username: ", "yellow"))
                            master_password = getpass.getpass(colored("[*] Master password: ", "yellow"))
                            encryption_key = getpass.getpass(colored("[*] Encryption key: ", "yellow"))
                            password_manager.login(username, master_password, encryption_key)
                        else:
                            print(colored("[-] You have not registered. Please do that.", "red"))

                    elif choice == 'help' or choice == 'h':
                        if password_manager.lockout_time and time.time() < password_manager.lockout_time:
                            clear_terminal()
                            print(colored(blehhh, "red"))
                            print(colored(f"[-] Account locked. WE'VE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(password_manager.lockout_time - time.time())} seconds.", "red"))
                            exit()
                        print(colored(""""[**] Available Commands:
'log' - Login (Mske sure you're registered before attempt to login)
'regis' - Register for new user (Only one user!)
'about' - More information about MIRA
'quit' - Terminate MIRA
'h' - Help""", "cyan"))

                    elif choice == 'dec_mnemonic':
                        if password_manager.lockout_time and time.time() < password_manager.lockout_time:
                            clear_terminal()
                            print(colored(blehhh, "red"))
                            print(colored(f"[-] Account locked. WE'VE ALREADY TOLD YOU THAT WE DON'T ACCEPT SHITTY BUGS HERE! If you are the real user, try again after {int(password_manager.lockout_time - time.time())} seconds.", "red"))
                            exit()
                        mnemonic_phrase = input(colored("[*] Mnemonic Phrase: ", "yellow"))
                        mnemonic = Mnemonic("english")
                        key_bytes = mnemonic.to_entropy(mnemonic_phrase)
                        key_base64 = base64.b64encode(key_bytes).decode()
                        print(colored(f"[+] Encryption Key: {key_base64}", "green"))

                    elif choice == 'quit':
                        print(colored("\n[-] Exiting Mira.....", "red"))
                        time.sleep(3)
                        clear_terminal()
                        print(colored(remember, "cyan"))
                        print(colored("Creating a password is like crafting a witty joke: it should be unique, memorable, and leave hackers scratching their heads. So, don't be shy to sprinkle a dash of humor into your password game – after all, laughter is the best encryption!", "cyan"))
                        exit()

                    elif choice == 'about':
                        clear_terminal()
                        print(colored(wolf, "blue"))
                        print(colored(about, "cyan"))

                    elif choice == 'clear':
                        clear_terminal()
                    else:
                        print(colored("[-] Invalid Option", "red"))

            except KeyboardInterrupt:
                print(colored("\n[-] Exiting Mira.....", "red"))
                time.sleep(3)
                clear_terminal()
                print(colored(remember, "cyan"))
                print(colored("Creating a password is like crafting a witty joke: it should be unique, memorable, and leave hackers scratching their heads. So, don't be shy to sprinkle a dash of humor into your password game – after all, laughter is the best encryption!", "cyan"))
                exit()
