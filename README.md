# SEC-440-Ransomware-Assignment

# Ransomware Proof of Concept

This proof-of-concept ransomware script is developed for educational purposes only and should not be used for any malicious activities.

## Overview

The `ransomware.py` script demonstrates a basic implementation of ransomware using Python. It encrypts and decrypts files within a specified directory using symmetric key encryption (AES) and RSA public-key encryption.

## Usage

### Encryption

- Ensure Python and the cryptography library are installed.

-Clone or download this repository.

-Customize the directory path (dir_path) in the script to the target directory where the .txt files are located.

-Run the script using python your_script_name.py.

-Review the console output for process notifications.

-Encrypted files will be saved with a .encrypted extension in the target directory.

### Decryption

- For the simulation is defaulted to instantly delte the file needed for decryption

- In order to access the needed file on line 96 `delete_smem_after_encryption = True  # Set to False to prevent deletion of 'smem_unencrypted.txt'` set delete smem_after_encryption to false
