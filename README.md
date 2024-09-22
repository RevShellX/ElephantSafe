🐘 ElephantSafe2.0 Password Generator (Updated Version)

ElephantSafe is a versatile and user-friendly terminal-based password generator built with a focus on security and ease of use. Featuring a unique blend of randomization techniques, hash-based checks, and customizable settings, ElephantSafe ensures your passwords are both strong and uncompromised, while incorporating some fun features like elephant ASCII art!

Features:
Secure Password Generation: Create strong passwords with custom lengths (up to 100 characters) and options to include/exclude symbols, numbers, and similar characters (e.g., 'I', 'l', 'O', '0').
Pronounceable Passwords: Generate easy-to-remember but secure passwords using alternating consonants and vowels.
Password Strength Check: Assess the strength of your password with a built-in strength meter and estimated cracking time ranging from "days" to "centuries."
Password History: Save your generated passwords along with timestamps and view the last 5 entries for easy retrieval.
Fun Facts: Enjoy random password-related facts to stay informed while securing your digital life.
ASCII Art: Display cool elephant art to remind you that your passwords are protected with the strength of an elephant!
GPG Encryption for Extra Security: Your passwords are now encrypted and saved in a GPG file, adding an extra layer of protection. No more plain text storage, ensuring that your sensitive data remains secure from unauthorized access.
Getting Started:
To generate a secure password, simply run the script and follow the prompts to specify the desired length and customize your settings:

bash
Copy code
python3 ElephantSafe.py
You will be prompted to:

Set password length (up to 100 characters, with a recommended minimum of 12).
Choose whether to include symbols, numbers, and exclude similar characters.
After generating the password, you’ll receive feedback on its strength, estimated cracking time, and whether it has been found in any known data breaches.

Example Output:
bash
Copy code
Generated Password: $TR0ngP@ssw0rd!  
Password Strength: Very Strong 💪💪💪💪💪  
Estimated time to crack: centuries  
Good news! This password hasn't been found in any known data breaches.  
Password has been securely saved in a GPG file.
Why ElephantSafe?
The name ElephantSafe reflects the robustness and security of your passwords—just like an elephant, strong and difficult to break. Whether you're generating secure passwords for everyday use or looking for pronounceable, memorable options, ElephantSafe has you covered.

License:
This project is licensed under the MIT License - see the LICENSE file for details.
