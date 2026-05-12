"""
Cryptographically secure password generator.

Why secrets instead of random?
- random module uses a PRNG (predictable with enough samples)
- secrets uses os.urandom() — cryptographically secure, unpredictable
- For passwords, predictability = vulnerability
"""

import secrets
import string


class PasswordGenerator:

    LOWERCASE  = string.ascii_lowercase          # a-z
    UPPERCASE  = string.ascii_uppercase          # A-Z
    DIGITS     = string.digits                   # 0-9
    SYMBOLS    = "!@#$%^&*()_+-=[]{}|;:,.<>?"   # special chars

    def generate(
        self,
        length: int = 16,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ) -> str:
        """
        Generates a secure random password.
        Guarantees at least one character from each selected category.
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")

        # Build the allowed character pool
        pool = self.LOWERCASE
        required = [secrets.choice(self.LOWERCASE)]

        if use_uppercase:
            pool += self.UPPERCASE
            required.append(secrets.choice(self.UPPERCASE))

        if use_digits:
            pool += self.DIGITS
            required.append(secrets.choice(self.DIGITS))

        if use_symbols:
            pool += self.SYMBOLS
            required.append(secrets.choice(self.SYMBOLS))

        # Fill remaining length from the full pool
        remaining = length - len(required)
        password_chars = required + [secrets.choice(pool) for _ in range(remaining)]

        # Shuffle to avoid predictable positions (e.g. first char always lowercase)
        secrets.SystemRandom().shuffle(password_chars)

        return "".join(password_chars)

    def evaluate_strength(self, password: str) -> dict:
        """
        Evaluates the strength of a given password.
        Returns a score (0-100) and a label.
        """
        score = 0
        feedback = []

        if len(password) >= 8:   score += 10
        if len(password) >= 12:  score += 15
        if len(password) >= 16:  score += 15

        if any(c.islower() for c in password):  score += 10
        if any(c.isupper() for c in password):  score += 15
        if any(c.isdigit() for c in password):  score += 15
        if any(c in self.SYMBOLS for c in password): score += 20

        if score < 40:
            label = "Weak"
        elif score < 70:
            label = "Medium"
        elif score < 90:
            label = "Strong"
        else:
            label = "Very Strong"

        return {"score": score, "label": label}