"""
Master password manager.
Handles vault initialization and authentication.

Flow:
  First run:  create_vault(password) → generates salt → derives key → stores salt+hash
  Next runs:  unlock_vault(password) → loads salt → re-derives key → compares hash
"""

from src.crypto.key_derivation import KeyDerivation
from src.database.db import DatabaseManager


class MasterPasswordManager:

    def __init__(self, db: DatabaseManager):
        self.db = db
        self.kd = KeyDerivation()
        self._session_key: bytes | None = None

    # ------------------------------------------------------------------ #
    #  Vault setup                                                         #
    # ------------------------------------------------------------------ #

    def is_vault_initialized(self) -> bool:
        """Returns True if a master password has already been set."""
        return self.db.get_config("salt") is not None

    def create_vault(self, master_password: str) -> None:
        """
        First-time setup: derives key from master password and
        stores the salt + key hash so we can verify future logins.
        The actual AES key is NEVER stored — only its hash.
        """
        self._validate_password_strength(master_password)

        salt = self.kd.generate_salt()
        key  = self.kd.derive_key(master_password, salt)

        # Store salt (needed to re-derive key on next login)
        self.db.set_config("salt", salt)
        # Store key hash (used only to verify the password is correct)
        self.db.set_config("key_hash", key)

        self._session_key = key

    # ------------------------------------------------------------------ #
    #  Authentication                                                      #
    # ------------------------------------------------------------------ #

    def unlock_vault(self, master_password: str) -> bool:
        """
        Verifies the master password and loads the session key into memory.
        Returns True on success, False on wrong password.
        """
        salt       = self.db.get_config("salt")
        stored_hash = self.db.get_config("key_hash")

        if salt is None or stored_hash is None:
            raise RuntimeError("Vault not initialized. Run create_vault() first.")

        is_valid = self.kd.verify_password(master_password, salt, stored_hash)

        if is_valid:
            self._session_key = self.kd.derive_key(master_password, salt)

        return is_valid

    def lock_vault(self) -> None:
        """Clears the session key from memory (auto-lock)."""
        self._session_key = None

    def get_session_key(self) -> bytes:
        """Returns the current session key or raises if vault is locked."""
        if self._session_key is None:
            raise PermissionError("Vault is locked. Please authenticate first.")
        return self._session_key

    @property
    def is_unlocked(self) -> bool:
        return self._session_key is not None

    # ------------------------------------------------------------------ #
    #  Password strength validation                                        #
    # ------------------------------------------------------------------ #

    def _validate_password_strength(self, password: str) -> None:
        errors = []
        if len(password) < 12:
            errors.append("At least 12 characters")
        if not any(c.isupper() for c in password):
            errors.append("At least one uppercase letter")
        if not any(c.islower() for c in password):
            errors.append("At least one lowercase letter")
        if not any(c.isdigit() for c in password):
            errors.append("At least one number")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("At least one special character")

        if errors:
            raise ValueError("Weak master password:\n  - " + "\n  - ".join(errors))