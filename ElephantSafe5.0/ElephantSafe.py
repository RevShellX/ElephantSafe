import os
import string
import datetime
import base64
import secrets
import getpass
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.fernet import Fernet
import gnupg
import bcrypt
import nacl.utils
from nacl.public import PrivateKey
import httpx
import hmac
from dotenv import load_dotenv
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from nacl.signing import SigningKey

from typing import List, Tuple, Optional, Union

load_dotenv()

gpg = gnupg.GPG()

def display_elephant_art() -> None:
    """Displays an ASCII art header for the password generator."""
    print(r"""
     __                                  
    '. \                                 
     '- \                                
      / /_         .---.         ______   
     / | \,\/--.//    )      .' Secure '. 
     |  \//        )/  /     /  # Hash #  \  
     \  ' ^ ^    /    )_____/   SafeLock  | 
      '.____.    .___/         \________.'  
         .\\/      #######       ___|_|__      
          '\      #     #       |  O  O |     
          _/ \/    #     #     |    |    |    
         /#  .!    #######     / \   |   / \  
         \  C// #  /'-----''/ #\  |  / #\ 
      .   'C/ |    |    |   |    | |  |    |mrf  ,
      \), .. .'OOO-'. ..'OOO'OOO-'. ..\(,  
    
    ElephantSafe Password Generator
    Created by CorleoneScript (https://github.com/CorleoneScript)
    Safe and Unique Passwords in your Terminal
    """)

def generate_password(length: int, use_symbols: bool, use_numbers: bool, exclude_similar: bool = False) -> str:
    """
    Generates a random password based on specified criteria.

    Args:
        length (int): The length of the password.
        use_symbols (bool): Whether to include symbols.
        use_numbers (bool): Whether to include numbers.
        exclude_similar (bool): Whether to exclude similar characters.

    Returns:
        str: The generated password.
    """
    characters = string.ascii_letters
    if use_symbols:
        characters += string.punctuation
    if use_numbers:
        characters += string.digits
    
    if exclude_similar:
        characters = ''.join(c for c in characters if c not in 'Il1O0')
    
    return ''.join(secrets.choice(characters) for _ in range(length))

def check_password_strength(password: str) -> Tuple[str, str, str]:
    """
    Evaluates the strength of the generated password.

    Args:
        password (str): The password to evaluate.

    Returns:
        Tuple[str, str, str]: Strength, cracking time, and feedback.
    """
    score = sum([
        len(password) >= 12,
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password)
    ])
    
    strengths = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    cracking_times = ["seconds", "days", "years", "decades", "centuries"]
    
    score = min(score, len(strengths) - 1)
    
    feedback = f"Your password is {strengths[score]}. It would take {cracking_times[score]} to crack."
    if score < 3:
        feedback += " Consider using a longer password with a mix of uppercase, lowercase, numbers, and symbols."
    
    return strengths[score], cracking_times[score], feedback

def secure_input(prompt: str) -> str:
    """
    Prompts the user for input securely (without echoing).

    Args:
        prompt (str): The prompt to display.

    Returns:
        str: The user's input.
    """
    return getpass.getpass(prompt)

def generate_key(master_password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Generates a secure encryption key based on the master password.

    Args:
        master_password (str): The master password.
        salt (Optional[bytes]): The salt for key derivation.

    Returns:
        Tuple[bytes, bytes]: The derived key and salt.
    """
    if salt is None:
        salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt

def encrypt_password(password: str, key: bytes) -> str:
    """
    Encrypts a password using ChaCha20-Poly1305.

    Args:
        password (str): The password to encrypt.
        key (bytes): The encryption key.

    Returns:
        str: The encrypted password.

    Raises:
        ValueError: If encryption fails.
    """
    try:
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, password.encode(), None)
        return base64.urlsafe_b64encode(nonce + ciphertext).decode()
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    """
    Decrypts a password using ChaCha20-Poly1305.

    Args:
        encrypted_password (str): The encrypted password.
        key (bytes): The decryption key.

    Returns:
        str: The decrypted password.

    Raises:
        ValueError: If decryption fails.
    """
    try:
        data = base64.urlsafe_b64decode(encrypted_password.encode())
        nonce, ciphertext = data[:12], data[12:]
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ciphertext, None).decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def secure_erase(variable: Union[str, bytes]) -> None:
    """
    Overwrites sensitive data in memory.

    Args:
        variable (Union[str, bytes]): The variable to erase.
    """
    if isinstance(variable, str):
        variable = bytearray(variable.encode())
    elif isinstance(variable, bytes):
        variable = bytearray(variable)
    
    for i in range(len(variable)):
        variable[i] = 0
    del variable

def save_password_with_gpg(service: str, password: str, master_password: str) -> None:
    """
    Saves an encrypted password using GPG.

    Args:
        service (str): The service name.
        password (str): The password to save.
        master_password (str): The master password.
    """
    salt = os.urandom(32)
    key, _ = generate_key(master_password, salt)
    encrypted_password = encrypt_password(password, key)
    timestamp = datetime.datetime.now().isoformat()
    data_to_encrypt = f"{timestamp}|{service}|{base64.urlsafe_b64encode(salt).decode()}|{encrypted_password}\n"

    encrypted_data = gpg.encrypt(data_to_encrypt, symmetric='AES256', passphrase=master_password)
    with open('saved_passwords.gpg', 'ab') as f:
        f.write(str(encrypted_data).encode())
    
    secure_erase(key)
    secure_erase(master_password)
    secure_erase(password)

def hash_master_password(password: str) -> bytes:
    """
    Hash the master password using bcrypt.

    Args:
        password (str): The master password.

    Returns:
        bytes: The hashed password.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_master_password(stored_hash: bytes, provided_password: str) -> bool:
    """
    Verify the provided password against the stored hash.

    Args:
        stored_hash (bytes): The stored hashed password.
        provided_password (str): The password to verify.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    return bcrypt.checkpw(provided_password.encode(), stored_hash)

def generate_keypair() -> Tuple[PrivateKey, nacl.public.PublicKey]:
    """
    Generate a public-private key pair using PyNaCl.

    Returns:
        Tuple[PrivateKey, nacl.public.PublicKey]: The private and public keys.
    """
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

async def fetch_password_policy(url: str) -> dict:
    """
    Asynchronously fetch password policy from a server.

    Args:
        url (str): The URL to fetch the policy from.

    Returns:
        dict: The password policy as a dictionary.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.json()

def create_hmac(key: bytes, message: str) -> str:
    """
    Create an HMAC for message authentication.

    Args:
        key (bytes): The HMAC key.
        message (str): The message to authenticate.

    Returns:
        str: The HMAC digest.
    """
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an RSA key pair using PyCryptodome.

    Returns:
        Tuple[bytes, bytes]: The private and public keys.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message_rsa(message: str, private_key: bytes) -> bytes:
    """
    Sign a message using RSA with PyCryptodome.

    Args:
        message (str): The message to sign.
        private_key (bytes): The private key.

    Returns:
        bytes: The RSA signature.
    """
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature_rsa(message: str, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an RSA signature using PyCryptodome.

    Args:
        message (str): The signed message.
        signature (bytes): The RSA signature.
        public_key (bytes): The public key.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def generate_ed25519_keypair() -> Tuple[SigningKey, nacl.signing.VerifyKey]:
    """
    Generate an Ed25519 key pair using PyNaCl.

    Returns:
        Tuple[SigningKey, nacl.signing.VerifyKey]: The signing and verification keys.
    """
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return signing_key, verify_key

def sign_message_ed25519(message: str, signing_key: SigningKey) -> bytes:
    """
    Sign a message using Ed25519 with PyNaCl.

    Args:
        message (str): The message to sign.
        signing_key (SigningKey): The Ed25519 signing key.

    Returns:
        bytes: The Ed25519 signature.
    """
    return signing_key.sign(message.encode())

def verify_signature_ed25519(message: str, signed: bytes, verify_key: nacl.signing.VerifyKey) -> bool:
    """
    Verify an Ed25519 signature using PyNaCl.

    Args:
        message (str): The signed message.
        signed (bytes): The Ed25519 signature.
        verify_key (nacl.signing.VerifyKey): The Ed25519 verification key.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        verify_key.verify(signed)
        return True
    except nacl.exceptions.BadSignatureError:
        return False

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.

    Args:
        length (int): The length of the token in bytes.

    Returns:
        str: The secure random token.
    """
    return secrets.token_hex(length)

def generate_secure_salt() -> bytes:
    """
    Generate a secure random salt.

    Returns:
        bytes: The secure random salt.
    """
    return os.urandom(32)

def get_password_history(master_password: str) -> List[str]:
    """
    Retrieves the password history from the encrypted file.

    Args:
        master_password (str): The master password.

    Returns:
        List[str]: A list of password history entries.
    """
    try:
        with open('saved_passwords.gpg', 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = gpg.decrypt(encrypted_data, passphrase=master_password)
        if decrypted_data.ok:
            return decrypted_data.data.decode().splitlines()
        else:
            print("Error decrypting password history.")
            return []
    except FileNotFoundError:
        print("No password history found.")
        return []
    except Exception as e:
        print(f"Error reading password history: {e}")
        return []

class PasswordManager:
    def __init__(self, master_password: str):
        self.master_password = master_password
        self.key, self.salt = generate_key(master_password)

    def add_password(self, service: str, password: str) -> None:
        """
        Adds a new password for a service.

        Args:
            service (str): The service name.
            password (str): The password to store.
        """
        encrypted_password = encrypt_password(password, self.key)
        save_password_with_gpg(service, encrypted_password, self.master_password)

    def get_password(self, service: str) -> Optional[str]:
        """
        Retrieves a password for a service.

        Args:
            service (str): The service name.

        Returns:
            Optional[str]: The decrypted password or None if not found.
        """
        passwords = get_password_history(self.master_password)
        for entry in reversed(passwords):
            timestamp, stored_service, salt, encrypted_password = entry.split('|')
            if stored_service == service:
                return decrypt_password(encrypted_password, self.key)
        return None

    def list_services(self) -> List[str]:
        """
        Lists all stored services.

        Returns:
            List[str]: A list of service names.
        """
        passwords = get_password_history(self.master_password)
        return [entry.split('|')[1] for entry in passwords]

    def __del__(self):
        secure_erase(self.master_password)
        secure_erase(self.key)
        secure_erase(self.salt)

def main():
    display_elephant_art()
    print("For maximum security, a 64-character password is recommended.")
    
    while True:
        try:
            length = int(input("How long should the password be? (min 16, max 128 characters, recommended 64): "))
            if not (16 <= length <= 128):
                print("Please enter a valid length between 16 and 128.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a number.")

    use_symbols = input("Do you want to use symbols? (y/n): ").strip().lower() == 'y'
    use_numbers = input("Do you want to use numbers? (y/n): ").strip().lower() == 'y'
    exclude_similar = input("Do you want to exclude similar characters (I, l, 1, O, 0)? (y/n): ").strip().lower() == 'y'
    
    password = generate_password(length, use_symbols, use_numbers, exclude_similar)
    
    strength, cracking_time, feedback = check_password_strength(password)
    print(f"\nGenerated Password: {password}")
    print(f"Password Strength: {strength}")
    print(f"Estimated time to crack: {cracking_time}")
    print(f"Feedback: {feedback}")

    print("\nAdditional Secure Random Data:")
    print(f"Random integer (32 bits): {secrets.randbits(32)}")
    print(f"Random bytes (16 bytes): {secrets.token_bytes(16)}")
    print(f"Random hex string (16 bytes): {secrets.token_hex(16)}")
    print(f"Secure random token: {generate_secure_token()}")
    print(f"Secure salt: {generate_secure_salt().hex()}")

    salt = os.urandom(32)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    print(f"\nHashed password (first 16 bytes): {hashed_password[:16].hex()}")

    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)
    encrypted_password = fernet.encrypt(password.encode())
    print(f"\nFernet encrypted password: {encrypted_password}")

    print("\nDemonstrating additional cryptographic primitives:")

    rsa_private_key, rsa_public_key = generate_rsa_keypair()
    message = "Hello, RSA!"
    rsa_signature = sign_message_rsa(message, rsa_private_key)
    rsa_verified = verify_signature_rsa(message, rsa_signature, rsa_public_key)
    print(f"\nRSA Signature Verification: {rsa_verified}")

    ed25519_signing_key, ed25519_verify_key = generate_ed25519_keypair()
    message = "Hello, Ed25519!"
    ed25519_signed = sign_message_ed25519(message, ed25519_signing_key)
    ed25519_verified = verify_signature_ed25519(message, ed25519_signed, ed25519_verify_key)
    print(f"Ed25519 Signature Verification: {ed25519_verified}")

    if input("Do you want to use the password manager? (y/n): ").strip().lower() == 'y':
        master_password = secure_input("Enter your master password: ")
        manager = PasswordManager(master_password)

        while True:
            print("\nPassword Manager Menu:")
            print("1. Add a password")
            print("2. Get a password")
            print("3. List all services")
            print("4. Exit")

            choice = input("Enter your choice (1-4): ")

            if choice == '1':
                service = input("Enter the service name: ")
                password = secure_input("Enter the password: ")
                manager.add_password(service, password)
                print(f"Password for {service} has been added.")

            elif choice == '2':
                service = input("Enter the service name: ")
                password = manager.get_password(service)
                if password:
                    print(f"Password for {service}: {password}")
                else:
                    print(f"No password found for {service}")

            elif choice == '3':
                services = manager.list_services()
                print("Stored services:")
                for service in services:
                    print(f"- {service}")

            elif choice == '4':
                break

            else:
                print("Invalid choice. Please try again.")

        del manager

    print("\nPassword Generation History:")
    if 'master_password' in locals():
        for entry in get_password_history(master_password)[-5:]:
            print(entry)
    else:
        print("No saved passwords to display.")

    secure_erase(password)
    secure_erase(master_password)

if __name__ == "__main__":
    main()
