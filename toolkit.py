# 🔒 Beginner Python Security Toolkit

import re
from cryptography.fernet import Fernet

# ----------------------------
# 1. Basic Firewall Simulation
# ----------------------------
allowed_ips = ["192.168.0.2"]
blocked_ips = ["192.168.1.10"]

def check_traffic(ip):
    if ip in blocked_ips:
        return f"{ip} is BLOCKED ❌"
    elif ip in allowed_ips:
        return f"{ip} is ALLOWED ✅"
    else:
        return f"{ip} is UNKNOWN ⚠️"

# ----------------------------
# 2. Secure File Encryption Tool
# ----------------------------
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    return open("secret.key", "rb").read()

def encrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)
    with open(filename, "rb") as file:
        data = file.read()
    encrypted = fernet.encr1ypt(data)
    with open(filename + ".encrypted", "wb") as file:
        file.write(encrypted)
    print(f"{filename} encrypted successfully.")

def decrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted = fernet.decrypt(encrypted_data)
    with open(filename.replace(".encrypted", ".decrypted"), "wb") as file:
        file.write(decrypted)
    print(f"{filename} decrypted successfully.")
``
# ---------------`-------------
# 3. Password Strength Checker
# ----------------------------
def check_password_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None

    score = 5 - sum([length_error, digit_error, uppercase_error, lowercase_error, symbol_error])
4

    if score == 5:
        return "Strong password 💪"
    elif 3 <= score < 5:
        return "Moderate password ⚠️"
    else:
        return "Weak password ❌"

# ----------------------------
# Menu System
# ----------------------------
def menu():
    while True:
        print("\n🔹 Python Security Toolkit 🔹")
        print("1. Firewall Simulation")
        print("2. File Encryption")
        print("3. File Decryption")
        print("4. Password Strength Checker")
        print("5. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            ip = input("Enter IP to check: ")
            print(check_traffic(ip))

        elif choice == "2":
            filename = input("Enter file name to encrypt: ")
            try:
                generate_key()
                encrypt_file(filename)
            except FileNotFoundError:
                print("File not found ❌")

        elif choice == "3":
            filename = input("Enter file name to decrypt: ")
            try:
                decrypt_file(filename)
            except FileNotFoundError:
                print("File not found ❌")

        elif choice == "4":
            password = input("Enter password to check: ")
            print(check_password_strength(password))

        elif choice == "5":
            print("Goodbye! 👋")
            break
        else:
            print("Invalid choice ❌")

if __name__ == "__main__":
    menu()
