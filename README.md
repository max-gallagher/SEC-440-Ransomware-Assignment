# SEC-440-Ransomware-Assignment

# Disclaimer

This is a proof of concept for ransomware meant for educational purposes only.

# Demonstration Video (Mitigation Demonstration Starts at 5:32)

[https://drive.google.com/file/d/1O4J3nnd1P3WOfX6RuaqjRWu5U-23nYX5/view?usp=sharing](https://drive.google.com/file/d/1O4J3nnd1P3WOfX6RuaqjRWu5U-23nYX5/view?usp=sharing)

(Mitigation Demonstration Starts at 5:32)

## Overview

The `ransomware.py` script demonstrates a basic implementation of ransomware using Python. It encrypts and decrypts files within a specified directory using symmetric key encryption (AES) and RSA public-key encryption.

# Usage

## Encryption

- Ensure Python and the cryptography library are installed.

- Clone or download this repository.

- Customize the directory path on line 100 (dir_path) in the script to the target directory where the .txt files are located.

- Run the script using python your_script_name.py.

- Review the console output for process notifications.

- Encrypted files will be saved with a .encrypted extension in the target directory.

## Decryption

- For the simulation is defaulted to instantly delte the file needed for decryption

- In order to access the needed file on line 96 `delete_smem_after_encryption = True  # Set to False to prevent deletion of 'smem_unencrypted.txt'` set delete smem_after_encryption to false

- The .encrypted file should now be deleted and it will be replaced with the correct .txt file

## Mitigation

When it comes to mitigating ransomware there are many routes you can take, the two that I went with were some of the simplest because I felt that they were the most successful against my attack and and some of the easiest to implement.

### Education (Educate users on what ransomware is and best practices to defend against it)

- Explain what ransomware is and how it works. Describe the encryption process that ransomware uses to lock files.

- Educate users about the common ways ransomware can infiltrate systems, such as phishing emails, malicious links, or hidden downloads.

- Emphasize the importance of reliable antivirus and anti-malware programs. Regularly update these tools to detect and prevent ransomware attacks.

- Educate users on how to identify suspicious emails, attachments, or links. Encourage them not to click on unknown links or download attachments from untrusted sources.

- Encourage the use of strong, unique passwords for different accounts. Educate users on creating complex passwords and using multi-factor authentication where possible.

- Encourage users to report the attack to IT or security personnel immediately to mitigate further damage.

### Windows Security Virus and Threat Protection: Anti Ransomware

- Windows Security's Virus and Threat Prodection features include "Ransomware Protection"

- This is how you access windows's "Controlder folder access" feature which by default is turned off, so **step 1 is to turn that on**.

- Once it is turned on you are able to enter the "Protected folders" menu, there are some folders that are protected by default but in this case you want to select any folder that contains important information.

- Protecting a folder will prevent changes to the files from outside applications unless they are put on a whitelist which can be managed through the "Allow an app through controlled folder access" option in the Ransomware protection tab.
