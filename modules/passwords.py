"""
modules/passwords.py - Password strength scoring and secure generation.
This module provides functions for analyzing password strength
and generating secure random passwords for Windows 11 systems.
"""

import secrets
import string
import re


def score_password_strength(password: str) -> dict:
    """
    Analyze password strength and return a score with details.
    
    Args:
        password: The password string to analyze
    
    Returns:
        dict with 'score' (0-100), 'length', 'has_upper', 'has_lower',
        'has_digit', 'has_special', 'has_common_pattern'
    """
    score = 0
    length = len(password)
    
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    # Pattern detection (common weak patterns)
    common_patterns = [
        r'(.)\1{2,}',  # 3+ same character
        r'(012|123|234|345|456|567|678|789|890)',  # sequential
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # letters
        r'(qwerty|asdf|zxcv|1234|qwer|asdf)',  # common keyboard patterns
    ]
    has_common_pattern = any(re.search(pattern, password.lower()) for pattern in common_patterns)
    
    # Scoring rules
    if length >= 8:
        score += 20
    elif length >= 6:
        score += 10
    
    if has_upper:
        score += 15
    if has_lower:
        score += 15
    if has_digit:
        score += 15
    if has_special:
        score += 15
    
    if not has_common_pattern:
        score += 15
    
    # Cap at 100
    return {
        'score': min(score, 100),
        'length': length,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_special': has_special,
        'has_common_pattern': has_common_pattern,
        'rating': get_rating(score)
    }


def get_rating(score: int) -> str:
    """Convert numeric score to human-readable rating."""
    if score >= 80:
        return "Strong"
    elif score >= 60:
        return "Moderate"
    elif score >= 40:
        return "Weak"
    else:
        return "Very Weak"


def generate_secure_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure random password.
    
    Args:
        length: Desired password length (default 16)
    
    Returns:
        Secure random password string
    
    Raises:
        ValueError: If length < 8
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")
    
    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # Ensure at least one character from each category
    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill remaining length with random characters from all sets
    all_chars = uppercase + lowercase + digits + special
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_chars))
    
    # Shuffle to avoid predictable patterns
    password_chars = list(password_chars)
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
    
    return ''.join(password_chars)
