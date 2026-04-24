"""
Tests for Module 3: Digital Signatures for Vault Integrity (sign_verify.py)
Covers: signing, verification, tamper detection, cross-user isolation.
"""

import os
import json
import shutil
import pytest

from keygen import generate_elgamal_keypair
from sign_verify import sign_vault, verify_vault


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
USER_A = "test_sign_userA"
USER_B = "test_sign_userB"
SAMPLE_DATA = "encryptedvaultcontentsabcdef1234567890"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def setup_users():
    _clean(USER_A)
    _clean(USER_B)
    generate_elgamal_keypair(USER_A)
    generate_elgamal_keypair(USER_B)
    yield
    _clean(USER_A)
    _clean(USER_B)


def _clean(user):
    shutil.rmtree(os.path.join("data", user), ignore_errors=True)
    pub = f"{user}_public.json"
    if os.path.exists(pub):
        os.remove(pub)


def _sign_and_split(user, data):
    """Helper: sign data and return (r, s) strings."""
    sig = sign_vault(user, data)
    parts = sig.split(":")
    assert len(parts) == 2, f"Expected 'r:s' signature format, got: {sig}"
    return parts[0], parts[1]


# ---------------------------------------------------------------------------
# 1. Signature format
# ---------------------------------------------------------------------------
class TestSignatureFormat:
    def test_sign_returns_string(self):
        sig = sign_vault(USER_A, SAMPLE_DATA)
        assert isinstance(sig, str)

    def test_signature_has_colon_separator(self):
        sig = sign_vault(USER_A, SAMPLE_DATA)
        assert ":" in sig, "Signature should be in 'r:s' format separated by ':'"

    def test_signature_has_exactly_two_parts(self):
        sig = sign_vault(USER_A, SAMPLE_DATA)
        parts = sig.split(":")
        assert len(parts) == 2

    def test_r_and_s_are_numeric_strings(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        assert r.isdigit(), f"r should be a numeric string, got: {r}"
        assert s.isdigit(), f"s should be a numeric string, got: {s}"

    def test_r_and_s_are_nonzero(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        assert int(r) != 0
        assert int(s) != 0


# ---------------------------------------------------------------------------
# 2. Verification — valid cases
# ---------------------------------------------------------------------------
class TestVerifyValid:
    def test_valid_signature_returns_true(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        assert verify_vault(USER_A, SAMPLE_DATA, r, s) is True

    def test_valid_signature_on_empty_string(self):
        r, s = _sign_and_split(USER_A, "")
        assert verify_vault(USER_A, "", r, s) is True

    def test_valid_signature_on_long_data(self):
        long_data = "x" * 10_000
        r, s = _sign_and_split(USER_A, long_data)
        assert verify_vault(USER_A, long_data, r, s) is True

    def test_sign_and_verify_multiple_times(self):
        for i in range(5):
            data = f"vault_content_{i}"
            r, s = _sign_and_split(USER_A, data)
            assert verify_vault(USER_A, data, r, s) is True


# ---------------------------------------------------------------------------
# 3. Verification — tamper detection
# ---------------------------------------------------------------------------
class TestTamperDetection:
    def test_appended_character_fails(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        assert verify_vault(USER_A, SAMPLE_DATA + "X", r, s) is False

    def test_prepended_character_fails(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        assert verify_vault(USER_A, "Z" + SAMPLE_DATA, r, s) is False

    def test_single_bit_change_fails(self):
        data = "AAAAAAAAAA"
        r, s = _sign_and_split(USER_A, data)
        tampered = "AAAAAAAAAB"
        assert verify_vault(USER_A, tampered, r, s) is False

    def test_completely_different_data_fails(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        assert verify_vault(USER_A, "totally_different_content", r, s) is False

    def test_empty_vs_non_empty_fails(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        assert verify_vault(USER_A, "", r, s) is False

    def test_modified_r_fails(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        bad_r = str(int(r) + 1)
        assert verify_vault(USER_A, SAMPLE_DATA, bad_r, s) is False

    def test_modified_s_fails(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        bad_s = str(int(s) + 1)
        assert verify_vault(USER_A, SAMPLE_DATA, r, bad_s) is False

    def test_swapped_r_and_s_fails(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        if r != s:
            assert verify_vault(USER_A, SAMPLE_DATA, s, r) is False


# ---------------------------------------------------------------------------
# 4. Cross-user isolation
# ---------------------------------------------------------------------------
class TestCrossUserIsolation:
    def test_user_b_signature_fails_user_a_verification(self):
        """A signature made by User B must not verify against User A's public key."""
        r, s = _sign_and_split(USER_B, SAMPLE_DATA)
        assert verify_vault(USER_A, SAMPLE_DATA, r, s) is False

    def test_user_a_signature_fails_user_b_verification(self):
        r, s = _sign_and_split(USER_A, SAMPLE_DATA)
        assert verify_vault(USER_B, SAMPLE_DATA, r, s) is False

    def test_each_user_can_verify_own_signature(self):
        for user in (USER_A, USER_B):
            r, s = _sign_and_split(user, SAMPLE_DATA)
            assert verify_vault(user, SAMPLE_DATA, r, s) is True


# ---------------------------------------------------------------------------
# 5. Signature uniqueness / randomness
# ---------------------------------------------------------------------------
class TestSignatureRandomness:
    def test_two_signatures_of_same_data_differ(self):
        """ElGamal signatures use random k — same message should produce different (r,s)."""
        sig1 = sign_vault(USER_A, SAMPLE_DATA)
        sig2 = sign_vault(USER_A, SAMPLE_DATA)
        # Both must still be valid
        r1, s1 = sig1.split(":")
        r2, s2 = sig2.split(":")
        assert verify_vault(USER_A, SAMPLE_DATA, r1, s1) is True
        assert verify_vault(USER_A, SAMPLE_DATA, r2, s2) is True
        # They should be different (probabilistic — could theoretically collide)
        assert sig1 != sig2, "Two signatures of the same data should differ (random k)"


# ---------------------------------------------------------------------------
# 6. Integration with vault file structure
# ---------------------------------------------------------------------------
class TestSignatureVaultIntegration:
    def test_vault_file_signature_field_is_valid(self):
        """After a vault operation, the stored signature must verify correctly."""
        from vault import add_credential

        master_pw = "MasterPW!"
        add_credential(USER_A, master_pw, "example.com", "user", "pw")

        vault_path = os.path.join("data", USER_A, "vault.json")
        assert os.path.exists(vault_path)

        with open(vault_path) as f:
            vault_data = json.load(f)

        encrypted_vault = vault_data["encrypted_vault"]
        r, s = vault_data["signature"].split(":")
        assert verify_vault(USER_A, encrypted_vault, r, s) is True

    def test_manual_edit_to_vault_file_breaks_signature(self):
        """Editing the vault JSON by hand must cause verify_vault to return False."""
        from vault import add_credential

        master_pw = "MasterPW!"
        add_credential(USER_A, master_pw, "tamper.com", "user", "pw")

        vault_path = os.path.join("data", USER_A, "vault.json")
        with open(vault_path) as f:
            vault_data = json.load(f)

        # Tamper with the encrypted content
        vault_data["encrypted_vault"] = vault_data["encrypted_vault"] + "TAMPERED"

        r, s = vault_data["signature"].split(":")
        assert verify_vault(USER_A, vault_data["encrypted_vault"], r, s) is False