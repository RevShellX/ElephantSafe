import random
import string
import requests
import hashlib
import datetime
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import gnupg

gpg = gnupg.GPG()

def display_elephant_art():
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

def generate_password(length, use_symbols, use_numbers, exclude_similar=False):
    characters = string.ascii_letters
    if use_symbols:
        characters += string.punctuation
    if use_numbers:
        characters += string.digits
    
    if exclude_similar:
        characters = ''.join(c for c in characters if c not in 'Il1O0')
    
    while True:
        password = ''.join(random.choice(characters) for _ in range(length))
        if (len(password) >= 8 and
            any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            (any(c.isdigit() for c in password) or not use_numbers) and
            (any(c in string.punctuation for c in password) or not use_symbols)):
            return password

def check_password_strength(password):
    score = 0
    if len(password) >= 12:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1
    
    strength = ""
    if score == 5:
        strength = "Very Strong"
        cracking_time = "centuries"
    elif score == 4:
        strength = "Strong"
        cracking_time = "decades"
    elif score == 3:
        strength = "Moderate"
        cracking_time = "years"
    else:
        strength = "Weak"
        cracking_time = "days or less"
    
    return strength, cracking_time

def check_password_compromised(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
    return 0

def generate_key(master_password):
    salt = b'elephantsafe_salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def encrypt_password(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

def save_password_with_gpg(service, password, master_password):
    key = generate_key(master_password)
    encrypted_password = encrypt_password(password, key)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_to_encrypt = f"{timestamp} | {service}: {encrypted_password}\n"

    with open('saved_passwords.gpg', 'ab') as f:
        encrypted_data = gpg.encrypt(data_to_encrypt, recipients=None, symmetric=True, passphrase=master_password)
        f.write(str(encrypted_data).encode())

def get_password_history(master_password):
    try:
        with open('saved_passwords.gpg', 'rb') as f:
            encrypted_data = f.read()
            decrypted_data = gpg.decrypt(encrypted_data, passphrase=master_password)
            entries = decrypted_data.data.decode().splitlines()[-5:]  # Last 5 entries
            return entries
    except FileNotFoundError:
        return []

def main():
    display_elephant_art()
    print("For maximum security, a 64-character password is recommended.")
    
    while True:
        try:
            length = int(input("How long should the password be? (max 100 characters, recommended 64): "))
            if length > 100:
                length = 100
                print("Maximum length is 100 characters. Using 100 characters.")
            elif length < 12:
                print("Warning: Passwords shorter than 12 characters are considered weak.")
            break
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 100.")
    
    use_symbols = input("Do you want to use symbols? (y/n): ").lower() == 'y'
    use_numbers = input("Do you want to use numbers? (y/n): ").lower() == 'y'
    
    exclude_similar = input("Do you want to exclude similar characters (I, l, 1, O, 0)? (y/n): ").lower() == 'y'
    password = generate_password(length, use_symbols, use_numbers, exclude_similar)
    
    strength, cracking_time = check_password_strength(password)
    compromised_count = check_password_compromised(password)
    
    print(f"\nGenerated Password: {password}")
    print(f"Password Strength: {strength}")
    print(f"Estimated time to crack: {cracking_time}")
    
    if compromised_count > 0:
        print(f"Warning: This password has been compromised {compromised_count} times.")
    else:
        print("Good news! This password hasn't been found in any known data breaches.")
    
    save_option = input("Do you want to save this password? (y/n): ").lower()
    if save_option == 'y':
        service = input("Enter the name of the service this password is for: ")
        master_password = input("Enter a master password to encrypt your passwords: ")
        save_password_with_gpg(service, password, master_password)
        print(f"Password for {service} has been saved securely in GPG format.")
    
    print("\nPassword Generation History:")
    if save_option == 'y':
        for entry in get_password_history(master_password):
            print(entry)
    else:
        print("No saved passwords to display.")

if __name__ == "__main__":
    main()
