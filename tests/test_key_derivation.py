"""
Tests for PBKDF2 key derivation module.
"""

import pytest
from src.crypto.key_derivation import KeyDerivation


@pytest.fixture
def kd():
    return KeyDerivation()


class TestKeyDerivation:

    def test_generate_salt_returns_32_bytes(self, kd):
        salt = kd.generate_salt()
        assert len(salt) == 32

    def test_generate_salt_is_random(self, kd):
        """Two salts should never be equal."""
        assert kd.generate_salt() != kd.generate_salt()

    def test_derive_key_returns_32_bytes(self, kd):
        salt = kd.generate_salt()
        key = kd.derive_key("MyPassword@123", salt)
        assert len(key) == 32

    def test_same_password_same_salt_returns_same_key(self, kd):
        salt = kd.generate_salt()
        key1 = kd.derive_key("MyPassword@123", salt)
        key2 = kd.derive_key("MyPassword@123", salt)
        assert key1 == key2

    def test_same_password_different_salt_returns_different_key(self, kd):
        key1 = kd.derive_key("MyPassword@123", kd.generate_salt())
        key2 = kd.derive_key("MyPassword@123", kd.generate_salt())
        assert key1 != key2

    def test_verify_password_correct(self, kd):
        salt = kd.generate_salt()
        key = kd.derive_key("MyPassword@123", salt)
        assert kd.verify_password("MyPassword@123", salt, key) is True

    def test_verify_password_wrong(self, kd):
        salt = kd.generate_salt()
        key = kd.derive_key("MyPassword@123", salt)
        assert kd.verify_password("WrongPassword@123", salt, key) is False