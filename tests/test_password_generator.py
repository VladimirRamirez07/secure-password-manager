"""
Tests for the password generator module.
"""

import pytest
from src.utils.password_generator import PasswordGenerator


@pytest.fixture
def gen():
    return PasswordGenerator()


class TestPasswordGenerator:

    def test_default_length(self, gen):
        pwd = gen.generate()
        assert len(pwd) == 16

    def test_custom_length(self, gen):
        pwd = gen.generate(length=24)
        assert len(pwd) == 24

    def test_minimum_length_enforced(self, gen):
        with pytest.raises(ValueError):
            gen.generate(length=4)

    def test_contains_uppercase(self, gen):
        pwd = gen.generate(use_uppercase=True)
        assert any(c.isupper() for c in pwd)

    def test_contains_digits(self, gen):
        pwd = gen.generate(use_digits=True)
        assert any(c.isdigit() for c in pwd)

    def test_contains_symbols(self, gen):
        pwd = gen.generate(use_symbols=True)
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        assert any(c in symbols for c in pwd)

    def test_no_symbols_when_disabled(self, gen):
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        for _ in range(20):
            pwd = gen.generate(use_symbols=False)
            assert not any(c in symbols for c in pwd)

    def test_passwords_are_unique(self, gen):
        """Cryptographic randomness — no two passwords should be equal."""
        passwords = {gen.generate() for _ in range(100)}
        assert len(passwords) == 100

    def test_evaluate_strength_very_strong(self, gen):
        result = gen.evaluate_strength("MyStr0ng!Pass@2026")
        assert result["label"] == "Very Strong"
        assert result["score"] >= 90

    def test_evaluate_strength_weak(self, gen):
        result = gen.evaluate_strength("abc")
        assert result["label"] == "Weak"

    def test_evaluate_strength_returns_score_and_label(self, gen):
        result = gen.evaluate_strength("Test@1234")
        assert "score" in result
        assert "label" in result