"""
AES-256-GCM encryption module.
Handles all encryption and decryption operations.

Why AES-256-GCM?
- AES-256: Industry standard, 256-bit key = 2^256 possible keys
- GCM mode: Authenticated encryption, protects integrity AND confidentiality
- Authentication tag: Detects any tampering with the ciphertext
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionManager:

    KEY_SIZE = 32       # 256 bits
    NONCE_SIZE = 12     # 96 bits — recommended for GCM

    def encrypt(self, key: bytes, plaintext: str) -> tuple[bytes, bytes]:
        """
        Encrypts plaintext using AES-256-GCM.
        Returns (ciphertext_with_tag, nonce).
        The last 16 bytes of ciphertext ARE the authentication tag (GCM appends it).
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")

        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return ciphertext, nonce

    def decrypt(self, key: bytes, ciphertext: bytes, nonce: bytes) -> str:
        """
        Decrypts AES-256-GCM ciphertext.
        Raises InvalidTag if the data was tampered with.
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")