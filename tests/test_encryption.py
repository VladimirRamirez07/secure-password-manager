"""
Tests for AES-256-GCM encryption module.
"""

import pytest
from src.crypto.encryption import EncryptionManager


@pytest.fixture
def enc():
    return EncryptionManager()


@pytest.fixture
def valid_key():
    import os
    return os.urandom(32)


class TestEncryptionManager:

    def test_encrypt_returns_ciphertext_and_nonce(self, enc, valid_key):
        ciphertext, nonce = enc.encrypt(valid_key, "secret123")
        assert isinstance(ciphertext, bytes)
        assert isinstance(nonce, bytes)
        assert len(nonce) == 12

    def test_decrypt_returns_original_plaintext(self, enc, valid_key):
        plaintext = "my_super_secret_password"
        ciphertext, nonce = enc.encrypt(valid_key, plaintext)
        result = enc.decrypt(valid_key, ciphertext, nonce)
        assert result == plaintext

    def test_ciphertext_differs_from_plaintext(self, enc, valid_key):
        plaintext = "password123"
        ciphertext, _ = enc.encrypt(valid_key, plaintext)
        assert ciphertext != plaintext.encode()

    def test_same_plaintext_produces_different_ciphertext(self, enc, valid_key):
        """Each encryption uses a random nonce — same input != same output."""
        ct1, n1 = enc.encrypt(valid_key, "same_password")
        ct2, n2 = enc.encrypt(valid_key, "same_password")
        assert ct1 != ct2
        assert n1 != n2

    def test_wrong_key_raises_exception(self, enc, valid_key):
        import os
        ciphertext, nonce = enc.encrypt(valid_key, "secret")
        wrong_key = os.urandom(32)
        with pytest.raises(Exception):
            enc.decrypt(wrong_key, ciphertext, nonce)

    def test_tampered_ciphertext_raises_exception(self, enc, valid_key):
        """GCM authentication tag should reject modified ciphertext."""
        ciphertext, nonce = enc.encrypt(valid_key, "secret")
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises(Exception):
            enc.decrypt(valid_key, tampered, nonce)

    def test_invalid_key_size_raises_value_error(self, enc):
        with pytest.raises(ValueError):
            enc.encrypt(b"short_key", "secret")