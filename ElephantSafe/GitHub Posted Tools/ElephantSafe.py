import random
import string
import requests
import hashlib
import math
import datetime
from itertools import chain

def display_elephant_art():
    print("""
     __                                  
    '. \\                                 
     '- \\                                
      / /_         .---.         ______   
     / | \\,\/--.//    )      .' Secure '. 
     |  \\//        )/  /     /  # Hash #  \\  
     \\  ' ^ ^    /    )_____/   SafeLock  | 
      '.____.    .___/         \\________.'  
         .\\/      #######       ___|_|__      
          '\\      #     #       |  O  O |     
          _/ \\/    #     #     |    |    |    
         /#  .!    #######     / \\   |   / \\  
         \\  C// #  /'-----''/ #\\  |  / #\\ 
      .   'C/ |    |    |   |    | |  |    |mrf  ,
      \\), .. .'OOO-'. ..'OOO'OOO-'. ..\\(,  
    
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

def generate_pronounceable_password(length):
    vowels = 'aeiou'
    consonants = ''.join(set(string.ascii_lowercase) - set(vowels))
    password = ''
    for i in range(length):
        if i % 2 == 0:
            password += random.choice(consonants)
        else:
            password += random.choice(vowels)
    return password.capitalize() + str(random.randint(0, 9)) + random.choice(string.punctuation)

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

def save_password(service, password):
    with open('saved_passwords.txt', 'a') as f:
        f.write(f"{service}: {password}\n")

def save_password_with_timestamp(service, password):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open('saved_passwords.txt', 'a') as f:
        f.write(f"{timestamp} | {service}: {password}\n")

def get_password_history():
    try:
        with open('saved_passwords.txt', 'r') as f:
            return f.readlines()[-5:]  # Return last 5 entries
    except FileNotFoundError:
        return []

def get_random_password_fact():
    facts = [
        "The most common password is '123456'. Don't use it!",
        "It would take a computer about 7 quintillion years to crack a 12-character password with numbers, upper and lowercase letters, and symbols.",
        "The average person has 100 passwords.",
        "62% of people use the same password for multiple accounts. Don't be one of them!",
        "A new password is hacked every 2 seconds."
    ]
    return random.choice(facts)

def emoji_strength_meter(strength):
    if strength == "Very Strong":
        return "💪💪💪💪💪"
    elif strength == "Strong":
        return "💪💪💪💪"
    elif strength == "Moderate":
        return "💪💪💪"
    else:
        return "💪"

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
    print(f"Password Strength: {strength} {emoji_strength_meter(strength)}")
    print(f"Estimated time to crack: {cracking_time}")
    
    if compromised_count > 0:
        print(f"Warning: This password has been compromised {compromised_count} times.")
    else:
        print("Good news! This password hasn't been found in any known data breaches.")
    
    save_option = input("Do you want to save this password? (y/n): ").lower()
    if save_option == 'y':
        service = input("Enter the name of the service this password is for: ")
        save_password_with_timestamp(service, password)
        print(f"Password for {service} has been saved.")
    
    print("\nPassword Generation History:")
    for entry in get_password_history():
        print(entry.strip())
    
    print("\nDid you know?")
    print(get_random_password_fact())
    
    print("\nRemember to change your passwords regularly for better security!")

if __name__ == "__main__":
    main()
