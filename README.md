# 🐘 ElephantSafe 2.0 Password Manager

A versatile and secure command-line password manager built in Python that combines strong encryption, customizable password generation, and user-friendly features. Using GPG encryption and modern cryptographic practices, ElephantSafe ensures your passwords remain secure while being easily accessible.

![ElephantSafe Logo](https://raw.githubusercontent.com/your-username/elephantsafe/main/logo.txt)

## Key Features

- 🔐 Secure Password Generation
  - Customizable length (16-128 characters)
  - Include/exclude symbols, numbers, and similar characters
  - Cryptographically secure random number generation using `secrets` module
  
- 🛡️ Enhanced Security
  - GPG encryption for secure storage
  - Unique salt generation for each password
  - Secure memory cleanup after usage
  - PBKDF2HMAC key derivation
  
- 📊 Advanced Password Analysis
  - Comprehensive strength assessment
  - Estimated cracking time calculation
  - Password history tracking
  
- 🎯 User Experience
  - Intuitive command-line interface
  - ASCII art elephant logo
  - Password viewing and management
  - Detailed feedback and strength metrics
  
- 💾 Storage Options
  - Secure GPG encrypted storage (recommended)
  - Plain text storage (for testing only)

## Requirements

- Python 3.x
- GPG (GnuPG) installed on your system
- Required Python packages (see requirements.txt):
  - python-gnupg
  - cryptography

## Installation

1. Clone or download this repository:
   ```powershell
   git clone https://github.com/your-username/elephantsafe.git
   cd elephantsafe
   ```

2. Install GnuPG on your system:
   - Windows: 
     ```powershell
     winget install GnuPG.GnuPG
     # Or download from https://www.gpg4win.org/
     ```
   - Linux: 
     ```bash
     sudo apt-get install gnupg
     ```
   - macOS: 
     ```bash
     brew install gnupg
     ```

3. Install Python requirements:
   ```powershell
   pip install -r requirements.txt
   ```

4. Verify GPG installation:
   ```powershell
   gpg --version
   ```

## Usage

### Quick Start
1. Run the script:
   ```powershell
   python Pass.py
   ```

2. Choose from the main menu:
   ```
   1. Generate and save a new password
   2. View password history
   3. Decrypt and view stored passwords
   4. Exit
   ```

### Example Usage

#### Generating a New Password:
```
Length: 64
Include symbols? y
Include numbers? y
Exclude similar characters? y

Generated Password: P@ssw0rd!123...
Strength: Very Strong 💪
Estimated cracking time: centuries
```

#### Viewing Stored Passwords:
```
1. github.com (saved on 2025-05-22T10:30:15)
2. email.com (saved on 2025-05-22T10:35:22)
...
```

### Generating a Password

1. Select option 1 from the main menu
2. Enter desired password length (16-128 characters)
3. Choose whether to include symbols and numbers
4. Opt to exclude similar characters if desired
5. Choose storage method (GPG encrypted or plain text)

### Viewing Stored Passwords

1. Select option 2 or 3 from the main menu
2. Enter your GPG master password when prompted
3. View your stored passwords securely

## Security Features

### Cryptographic Implementation
- GPG encryption with AES256 for secure storage
- `secrets` module for cryptographically secure random generation
- Unique salt generation for each password
- PBKDF2HMAC key derivation with SHA256
- Secure memory wiping after password usage

### Security Measures
- Password strength assessment with multiple criteria
- Secure password input handling
- No plaintext password storage in memory
- Screen clearing after sensitive data display
- Input validation and sanitization

## Password Storage

- Encrypted passwords are stored in `saved_passwords.gpg`
- Plain text passwords (for testing) are stored in `saved_passwords.txt`
- Each password entry includes timestamp and service name

## Best Practices

1. Always use GPG encryption for storing passwords
2. Use strong master passwords
3. Generate passwords of at least 16 characters
4. Include a mix of uppercase, lowercase, numbers, and symbols
5. Regularly backup your GPG keys and password file

## Disclaimer

The plain text storage option is provided for testing purposes only. Always use GPG encryption for storing sensitive information.

## Contributing

Feel free to submit issues and enhancement requests!

## License

[MIT License](LICENSE)

## Author

Your Name

---

🔐 Remember: Security is a journey, not a destination!
