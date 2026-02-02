import re
import random

# Mapping used to \"leetify\" characters when strengthening a password
leet_map = {
    "a": "@",
    "A": "@",
    "e": "3",
    "E": "3",
    "i": "!",
    "I": "!",
    "o": "0",
    "O": "0",
    "s": "$",
    "S": "$",
}

symbols = "!@#$%^&*()-=+[]{}?<>"
digits = "0123456789"


def password_strength(pw: str) -> int:
    """Return a score from 0–5 describing password complexity."""
    score = 0

    if len(pw) >= 8:
        score += 1
    if re.search(r"[A-Z]", pw):
        score += 1
    if re.search(r"[a-z]", pw):
        score += 1
    if re.search(r"[0-9]", pw):
        score += 1
    if re.search(r"[^a-zA-Z0-9]", pw):
        score += 1

    return score


def strengthen_password(pw: str) -> str:
    """
    Take a base password and strengthen it:
    - Randomly upper-case letters
    - Apply leet substitutions
    - Ensure at least one digit and symbol
    - Ensure final length >= 10
    """
    if not pw:
        return ""

    # Step 1: Start with original characters (possibly modified)
    new_pw = ""

    for char in pw:
        # Uppercase randomly
        if char.isalpha() and random.random() > 0.5:
            char = char.upper()

        # Apply leet substitutions
        if char in leet_map and random.random() > 0.3:
            char = leet_map[char]

        new_pw += char

    # Step 2: Ensure at least one digit
    if not re.search(r"[0-9]", new_pw):
        new_pw += random.choice(digits)

    # Step 3: Ensure at least one symbol
    if not re.search(r"[^a-zA-Z0-9]", new_pw):
        new_pw += random.choice(symbols)

    # Step 4: Ensure length ≥ 10 by appending random characters from original pw
    while len(new_pw) < 10 and pw:
        new_pw += random.choice(pw)

    return new_pw