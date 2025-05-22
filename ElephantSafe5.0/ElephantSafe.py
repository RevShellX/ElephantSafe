import os
import string
import base64
import secrets
import getpass
import hashlib
import datetime
import shutil
import gnupg
from typing import Tuple, Optional, List, Union

# Try to find gpg binary automatically
GPG_BINARY = shutil.which('gpg') or shutil.which('gpg.exe')
gpg = gnupg.GPG(gpgbinary=GPG_BINARY) if GPG_BINARY else gnupg.GPG()

# Print GPG diagnostics at startup
print(f"[GPG] Using binary: {GPG_BINARY}")
print(f"[GPG] Home directory: {gpg.gnupghome}")
version_info = gpg.version if hasattr(gpg, 'version') else 'Unknown'
print(f"[GPG] Version: {version_info}")

def display_elephant_art() -> None:
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
    Safe and Unique Passwords in your Terminal
    """)

def generate_password(length: int, use_symbols: bool, use_numbers: bool, exclude_similar: bool = False) -> str:
    characters = string.ascii_letters
    if use_symbols:
        characters += string.punctuation
    if use_numbers:
        characters += string.digits
    if exclude_similar:
        characters = ''.join(c for c in characters if c not in 'Il1O0')
    return ''.join(secrets.choice(characters) for _ in range(length))

def check_password_strength(password: str) -> Tuple[str, str, str]:
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
    return getpass.getpass(prompt)

def secure_erase(variable: Union[str, bytes]):
    if isinstance(variable, str):
        variable = bytearray(variable.encode())
    elif isinstance(variable, bytes):
        variable = bytearray(variable)
    for i in range(len(variable)):
        variable[i] = 0
    del variable

def save_password_gpg(service: str, password: str, master_password: str):
    timestamp = datetime.datetime.now().isoformat()
    data_to_encrypt = f"{timestamp}|{service}|{password}\n"
    
    # Use GPG to encrypt the data with a passphrase
    encrypted_data = gpg.encrypt(data_to_encrypt, recipients=None, symmetric='AES256', 
                               passphrase=master_password, armor=False)
    
    if encrypted_data.ok:
        try:
            with open('saved_passwords.gpg', 'ab') as f:
                f.write(encrypted_data.data)
            print(f"Password for '{service}' saved securely with GPG.")
        except Exception as e:
            print(f"Error saving encrypted password: {e}")
    else:
        print("GPG encryption failed:", getattr(encrypted_data, 'status', 'Unknown error'))
        print("GPG stderr:", getattr(encrypted_data, 'stderr', 'No error details'))

    secure_erase(master_password)
    secure_erase(password)

def save_password_plain(service: str, password: str):
    timestamp = datetime.datetime.now().isoformat()
    line = f"{timestamp}|{service}|{password}\n"
    with open('saved_passwords.txt', 'a') as f:
        f.write(line)

def get_password_history_gpg(master_password: str) -> List[str]:
    try:
        with open('saved_passwords.gpg', 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = gpg.decrypt(encrypted_data, passphrase=master_password)
        if decrypted_data.ok:
            return decrypted_data.data.decode().splitlines()
        else:
            print("Error decrypting password history:", getattr(decrypted_data, 'status', 'Unknown error'))
            print("GPG stderr:", getattr(decrypted_data, 'stderr', 'No error details'))
            return []
    except FileNotFoundError:
        print("No password history found.")
        return []
    except Exception as e:
        print(f"Error reading password history: {e}")
        return []

def get_password_history_plain() -> List[str]:
    try:
        with open('saved_passwords.txt', 'r') as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []

def decrypt_gpg_passwords(master_password: str) -> None:
    try:
        with open('saved_passwords.gpg', 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = gpg.decrypt(encrypted_data, passphrase=master_password)
        if decrypted_data.ok:
            passwords = decrypted_data.data.decode().splitlines()
            if not passwords:
                print("No passwords found.")
                return
            
            print("\nStored passwords:")
            for i, entry in enumerate(passwords, 1):
                timestamp, service, *_ = entry.split('|')
                print(f"{i}. {service} (saved on {timestamp})")
            
            while True:
                try:
                    choice = input("\nEnter the number of the password to view (or 'q' to quit): ").strip()
                    if choice.lower() == 'q':
                        break
                    
                    index = int(choice) - 1
                    if 0 <= index < len(passwords):
                        timestamp, service, password = passwords[index].split('|')
                        print(f"\nService: {service}")
                        print(f"Password: {password}")
                        print(f"Saved on: {timestamp}")
                        input("\nPress Enter to continue...")
                        # Clear the screen (on Windows)
                        os.system('cls')
                    else:
                        print("Invalid number. Please try again.")
                except ValueError:
                    print("Please enter a valid number.")
                except Exception as e:
                    print(f"Error: {e}")
        else:
            print("Error decrypting passwords:", getattr(decrypted_data, 'status', 'Unknown error'))
            print("GPG stderr:", getattr(decrypted_data, 'stderr', 'No error details'))
    except FileNotFoundError:
        print("No password file found.")
    except Exception as e:
        print(f"Error reading passwords: {e}")
    finally:
        secure_erase(master_password)

def main():
    display_elephant_art()
    print("For maximum security, a 64-character password is recommended.")

    # Main menu
    while True:
        print("\nWhat would you like to do?")
        print("1. Generate and save a new password")
        print("2. View password history")
        print("3. Decrypt and view stored passwords")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == '1':
            # Password generation logic
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

            # Save password menu
            print("\nHow would you like to save the password?")
            print("1. Securely with GPG encryption (recommended)")
            print("2. In plain text (not secure, for demonstration only)")
            print("3. Do not save, just show in terminal")
            save_choice = input("Enter your choice (1/2/3): ").strip()

            if save_choice == '1':
                master_password = secure_input("Enter your GPG master password: ")
                service = input("Enter the service name for this password: ")
                save_password_gpg(service, password, master_password)
                secure_erase(master_password)
            elif save_choice == '2':
                print("WARNING: Saving passwords in plain text is NOT secure!")
                service = input("Enter the service name for this password: ")
                save_password_plain(service, password)
            
            secure_erase(password)

        elif choice == '2':
            print("\nHow would you like to view the history?")
            print("1. GPG encrypted history")
            print("2. Plain text history")
            history_choice = input("Enter your choice (1/2): ").strip()
            
            if history_choice == '1':
                master_password = secure_input("Enter your GPG master password: ")
                for entry in get_password_history_gpg(master_password)[-5:]:
                    print(entry)
                secure_erase(master_password)
            elif history_choice == '2':
                for entry in get_password_history_plain()[-5:]:
                    print(entry)

        elif choice == '3':
            master_password = secure_input("Enter your GPG master password: ")
            decrypt_gpg_passwords(master_password)

        elif choice == '4':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
