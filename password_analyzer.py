#!/usr/bin/env python3
"""
Password Security Analyzer
Analyzes password strength and demonstrates hashing
"""

import hashlib
import re
from datetime import timedelta

# Common weak passwords (top 100)
COMMON_PASSWORDS = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 
    'password1', '12345678', '111111', '1234567', 'sunshine',
    'password123', 'welcome', 'admin', 'letmein', 'monkey'
]

def check_length(password):
    """Check password length"""
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
    """Check character variety"""
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
    """Check against common passwords"""
    if password.lower() in COMMON_PASSWORDS:
        return 'Critical', 'This is a commonly used password!'
    return 'Good', 'Not in common password list'

def estimate_crack_time(password):
    """Estimate time to crack (brute force)"""
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
    
    # Assuming 1 billion attempts per second
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
    """Generate hashes"""
    return {
        'MD5': hashlib.md5(password.encode()).hexdigest(),
        'SHA-256': hashlib.sha256(password.encode()).hexdigest(),
        'SHA-512': hashlib.sha512(password.encode()).hexdigest()[:64]
    }

def analyze_password(password):
    """Complete password analysis"""
    print("=" * 70)
    print("PASSWORD SECURITY ANALYSIS")
    print("=" * 70)
    print(f"Password: {'*' * len(password)}")
    print()
    
    # Length check
    rating, msg = check_length(password)
    print(f"Length ({len(password)} chars): [{rating}] {msg}")
    
    # Complexity check
    rating, msg = check_complexity(password)
    print(f"Complexity: [{rating}] {msg}")
    
    # Common password check
    rating, msg = check_common(password)
    print(f"Common Password: [{rating}] {msg}")
    
    # Crack time estimate
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
    print("Password Security Analyzer")
    print("=" * 70)
    
    while True:
        password = input("\nEnter password to analyze (or 'quit' to exit): ")
        
        if password.lower() == 'quit':
            print("Goodbye!")
            break
        
        if not password:
            print("Please enter a password.")
            continue
        
        analyze_password(password)

if __name__ == "__main__":
    main()
