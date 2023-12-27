# Little-shits - Destructive Encryption Worm

## Description
WormyCrypter is a potent Python script designed for destructive encryption and rapid propagation across directories. The script employs the Fernet symmetric encryption library to encrypt files in targeted directories, rendering them inaccessible.

## Usage
**Caution:** This script is likely destructive and intended for educational purposes only. Execute the script responsibly in a controlled environment to understand its impact.

To unleash the worm, execute the script with the following command:

```bash
python3 wormy_crypter.py --path /path/to/target/directory
```

## Features
- **Self-Replicating Worm:** WormyCrypter creates a malicious copy of itself (` .wrong.py`) in the same directory as the script, ensuring persistence.
  
- **Destructive Encryption:** The worm duplicates and encrypts files in targeted directories, making them irretrievable without the encryption key.

- **Encryption Algorithm:** Utilizes the Fernet symmetric encryption library for securing replicated files, making decryption without the key practically impossible.

## Disclaimer
This script is created for educational purposes to demonstrate the potential dangers of destructive malware. The author takes no responsibility for any misuse or damage caused by its execution.

## Requirements
- Python 3.x
- **cryptography** library (install with `pip install cryptography`)

## Warning
**Use at Your Own Risk:** Executing this script in a real-world scenario may result in irreversible data loss and legal consequences. Do not use this script for malicious purposes. Always seek proper authorization before conducting any testing or experiments.
