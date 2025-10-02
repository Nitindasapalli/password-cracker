#!/usr/bin/env python3
"""
password_strength.py
Simple password strength estimator based on charset and entropy.
"""

import argparse
import math
import string

def pool_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    # rough symbol count - treat common printable punctuation as set
    symbols = set(c for c in password if c in string.punctuation)
    if symbols:
        size += len(string.punctuation)  # ~32
    return size

def estimate_entropy(password: str) -> float:
    if not password:
        return 0.0
    pool = pool_size(password)
    if pool <= 0:
        return 0.0
    return len(password) * math.log2(pool)

def strength_label(bits: float) -> str:
    if bits < 28:
        return "Very weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Moderate"
    if bits < 80:
        return "Strong"
    return "Very strong"

def suggestions(password: str) -> list:
    s = []
    if len(password) < 8:
        s.append("Use at least 12 characters (passphrases are better).")
    if not any(c.islower() for c in password):
        s.append("Add lowercase letters.")
    if not any(c.isupper() for c in password):
        s.append("Add uppercase letters.")
    if not any(c.isdigit() for c in password):
        s.append("Include digits.")
    if not any(c in string.punctuation for c in password):
        s.append("Include symbols or punctuation.")
    if len(password) >= 12 and ' ' in password:
        s.append("Good: spaces can increase memorability of passphrases.")
    return s

def main():
    p = argparse.ArgumentParser(description="Password strength estimator")
    p.add_argument("password", help="Password to evaluate (wrap in quotes to include spaces)")
    args = p.parse_args()
    pw = args.password.strip()
    bits = estimate_entropy(pw)
    print(f"Password length: {len(pw)}")
    print(f"Estimated entropy: {bits:.1f} bits")
    print(f"Strength: {strength_label(bits)}")
    print("Recommendations:")
    for r in suggestions(pw):
        print(" -", r)

if __name__ == "__main__":
    main()
