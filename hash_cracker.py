#!/usr/bin/env python3
"""
hash_cracker.py
Simple wordlist-based hash cracker for MD5/SHA1/SHA256/SHA512.
Use only on hashes you own/created.
"""
import argparse
import hashlib
from pathlib import Path
from tqdm import tqdm  # optional progress bar; pip install tqdm

ALGOS = {"md5", "sha1", "sha256", "sha512"}

def compute_hash(text: str, alg: str) -> str:
    h = hashlib.new(alg)
    h.update(text.encode("utf-8", errors="ignore"))
    return h.hexdigest()

def try_crack(target_hash: str, alg: str, wordlist: Path, salt: str = "", salt_pos: str = "none"):
    target = target_hash.lower().strip()
    alg = alg.lower()
    if alg not in ALGOS:
        raise ValueError(f"Unsupported algorithm: {alg}")
    if not wordlist.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist}")

    with wordlist.open("r", errors="ignore") as f:
        for line in tqdm(f, desc="Trying words", unit="word"):
            candidate = line.strip()
            if not candidate:
                continue
            attempts = []
            # try without salt
            attempts.append(candidate)
            # salt prefix/suffix
            if salt:
                if salt_pos == "prefix":
                    attempts.append(salt + candidate)
                elif salt_pos == "suffix":
                    attempts.append(candidate + salt)
                elif salt_pos == "both":
                    attempts.append(salt + candidate + salt)
            for text in attempts:
                if compute_hash(text, alg) == target:
                    return text
    return None

def main():
    p = argparse.ArgumentParser(description="Simple wordlist-based hash cracker")
    p.add_argument("--hash", required=True, help="Target hash (hex)")
    p.add_argument("--alg", required=True, choices=list(ALGOS), help="Hash algorithm")
    p.add_argument("--wordlist", required=True, type=Path, help="Path to wordlist file")
    p.add_argument("--salt", default="", help="Optional salt string")
    p.add_argument("--salt-pos", choices=["none","prefix","suffix","both"], default="none",
                   help="Position of provided salt relative to candidate")
    args = p.parse_args()

    print("Starting crack attempt...")
    found = try_crack(args.hash, args.alg, args.wordlist, args.salt, args.salt_pos)
    if found:
        print(f"SUCCESS: password is: {found!r}")
    else:
        print("FAILED: password not found in wordlist.")

if __name__ == "__main__":
    main()
