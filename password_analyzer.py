#!/usr/bin/env python3
"""
Password Security Analyzer & Generator
Analyzes password strength and generates secure passwords
"""

import hashlib
import re
import secrets
import string

COMMON_PASSWORDS = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 
    'password1', '12345678', '111111', '1234567', 'sunshine',
    'password123', 'welcome', 'admin', 'letmein', 'monkey'
]

def check_length(password):
    length = len(password)
    if length < 8:
        return 'Weak', 'Too short (minimum 8 characters)'
    elif length < 12:
        return 'Fair', 'Consider 12+ characters'
    elif length < 16:
        return 'Good', 'Strong length'
    else:
        return 'Excellent', 'Very strong length'

def check_complexity(password):
    checks = {
        'lowercase': bool(re.search(r'[a-z]', password)),
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'numbers': bool(re.search(r'\d', password)),
        'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }
    score = sum(checks.values())
    if score == 1:
        return 'Weak', 'Only one character type'
    elif score == 2:
        return 'Fair', 'Add more character types'
    elif score == 3:
        return 'Good', 'Good variety'
    else:
        return 'Excellent', 'All character types used'

def check_common(password):
    if password.lower() in COMMON_PASSWORDS:
        return 'Critical', 'This is a commonly used password!'
    return 'Good', 'Not in common password list'

def estimate_crack_time(password):
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'\d', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        charset_size += 32
    if charset_size == 0:
        return 'N/A'
    attempts_per_sec = 1_000_000_000
    total_combinations = charset_size ** len(password)
    seconds = total_combinations / (2 * attempts_per_sec)
    if seconds < 1:
        return 'Instant'
    elif seconds < 60:
        return f'{int(seconds)} seconds'
    elif seconds < 3600:
        return f'{int(seconds/60)} minutes'
    elif seconds < 86400:
        return f'{int(seconds/3600)} hours'
    elif seconds < 31536000:
        return f'{int(seconds/86400)} days'
    else:
        years = int(seconds/31536000)
        return f'{years:,} years'

def hash_password(password):
    return {
        'MD5': hashlib.md5(password.encode()).hexdigest(),
        'SHA-256': hashlib.sha256(password.encode()).hexdigest(),
        'SHA-512': hashlib.sha512(password.encode()).hexdigest()[:64]
    }

def generate_password(length=16, use_upper=True, use_lower=True, use_numbers=True, use_special=True):
    """Generate a cryptographically secure random password"""
    chars = ''
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_numbers:
        chars += string.digits
    if use_special:
        chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    if not chars:
        chars = string.ascii_letters + string.digits
    
    password = ''.join(secrets.choice(chars) for _ in range(length))
    return password

def analyze_password(password):
    print("=" * 70)
    print("PASSWORD SECURITY ANALYSIS")
    print("=" * 70)
    print(f"Password: {'*' * len(password)}")
    print()
    rating, msg = check_length(password)
    print(f"Length ({len(password)} chars): [{rating}] {msg}")
    rating, msg = check_complexity(password)
    print(f"Complexity: [{rating}] {msg}")
    rating, msg = check_common(password)
    print(f"Common Password: [{rating}] {msg}")
    crack_time = estimate_crack_time(password)
    print(f"Estimated Crack Time: {crack_time}")
    print()
    print("-" * 70)
    print("PASSWORD HASHES")
    print("-" * 70)
    hashes = hash_password(password)
    for algo, hash_val in hashes.items():
        print(f"{algo:10}: {hash_val}")
    print()
    print("-" * 70)
    print("RECOMMENDATIONS")
    print("-" * 70)
    if len(password) < 12:
        print("• Use at least 12 characters")
    if not re.search(r'[A-Z]', password):
        print("• Add uppercase letters")
    if not re.search(r'[a-z]', password):
        print("• Add lowercase letters")
    if not re.search(r'\d', password):
        print("• Add numbers")
    if not re.search(r'[!@#$%^&*()]', password):
        print("• Add special characters")
    if password.lower() in COMMON_PASSWORDS:
        print("• NEVER use common passwords!")
    print("=" * 70)

def main():
    print("=" * 70)
    print("PASSWORD SECURITY TOOL")
    print("=" * 70)
    
    while True:
        print("\n1. Analyze a password")
        print("2. Generate a secure password")
        print("3. Quit")
        
        choice = input("\nSelect option (1-3): ")
        
        if choice == '1':
            password = input("\nEnter password to analyze: ")
            if password:
                analyze_password(password)
        
        elif choice == '2':
            print("\nPassword Generator")
            print("-" * 70)
            try:
                length = int(input("Length (12-32, default 16): ") or "16")
                length = max(12, min(32, length))
            except:
                length = 16
            
            use_upper = input("Include uppercase? (Y/n): ").lower() != 'n'
            use_lower = input("Include lowercase? (Y/n): ").lower() != 'n'
            use_numbers = input("Include numbers? (Y/n): ").lower() != 'n'
            use_special = input("Include special chars? (Y/n): ").lower() != 'n'
            
            password = generate_password(length, use_upper, use_lower, use_numbers, use_special)
            print("\n" + "=" * 70)
            print(f"Generated Password: {password}")
            print("=" * 70)
            print("\nAnalyzing generated password...")
            analyze_password(password)
        
        elif choice == '3':
            print("\nGoodbye!")
            break
        
        else:
            print("\nInvalid option. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    main()
