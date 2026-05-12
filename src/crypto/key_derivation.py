"""
Key derivation module using PBKDF2-HMAC-SHA256.

Why PBKDF2?
- Slow by design: makes brute-force attacks expensive
- 600,000 iterations: NIST recommendation for PBKDF2-SHA256 (2023)
- Salt: unique per vault, prevents rainbow table attacks
- Output: 32 bytes = exactly the AES-256 key size we need
"""

import os
import hashlib


class KeyDerivation:

    ITERATIONS = 600_000    # NIST recommended minimum (2023)
    KEY_LENGTH = 32         # 256 bits for AES-256
    SALT_SIZE = 32          # 256 bits of randomness

    def generate_salt(self) -> bytes:
        """Generates a cryptographically secure random salt."""
        return os.urandom(self.SALT_SIZE)

    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        """
        Derives a 256-bit AES key from the master password.
        Same password + same salt = same key (deterministic).
        Different salt = completely different key (why salt matters).
        """
        key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=master_password.encode("utf-8"),
            salt=salt,
            iterations=self.ITERATIONS,
            dklen=self.KEY_LENGTH,
        )
        return key

    def verify_password(self, master_password: str, salt: bytes,
                        stored_key_hash: bytes) -> bool:
        """
        Verifies the master password by re-deriving the key and comparing.
        Uses hmac.compare_digest to prevent timing attacks.
        """
        import hmac
        derived = self.derive_key(master_password, salt)
        return hmac.compare_digest(derived, stored_key_hash)