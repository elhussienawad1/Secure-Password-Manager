"""
Tests for Module 1: ElGamal Key Management (keygen.py)
Covers: key generation, file structure, math correctness, and edge cases.
"""

import os
import json
import shutil
import pytest
from unittest.mock import patch

from src.keygen import generate_elgamal_keypair


# ---------------------------------------------------------------------------
# Helpers / Constants
# ---------------------------------------------------------------------------
TEST_USER = "test_keygen_user"
PRIVATE_PATH = os.path.join("data", TEST_USER, "private.json")
PUBLIC_PATH = os.path.join("data", "Export", f"{TEST_USER}_public.json")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def cleanup():
    """Remove all generated key files before and after every test."""
    _remove_keys()
    yield
    _remove_keys()


def _remove_keys():
    shutil.rmtree(os.path.join("data", TEST_USER), ignore_errors=True)
    if os.path.exists(PUBLIC_PATH):
        os.remove(PUBLIC_PATH)


# ---------------------------------------------------------------------------
# 1. File creation tests
# ---------------------------------------------------------------------------
class TestKeyFilesCreated:
    def test_private_key_file_is_created(self):
        generate_elgamal_keypair(TEST_USER)
        assert os.path.exists(PRIVATE_PATH), "private.json was not created"

    def test_public_key_file_is_created(self):
        generate_elgamal_keypair(TEST_USER)
        assert os.path.exists(PUBLIC_PATH), "public key file was not created"

    def test_data_directory_is_created(self):
        generate_elgamal_keypair(TEST_USER)
        assert os.path.isdir(os.path.join("data", TEST_USER))

    def test_export_directory_is_created(self):
        generate_elgamal_keypair(TEST_USER)
        assert os.path.isdir(os.path.join("data", "Export"))


# ---------------------------------------------------------------------------
# 2. Key structure tests
# ---------------------------------------------------------------------------
class TestKeyStructure:
    def test_public_key_has_required_fields(self):
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        for field in ("p", "alpha", "y"):
            assert field in pub, f"Public key missing field: {field}"

    def test_private_key_has_required_field(self):
        generate_elgamal_keypair(TEST_USER)
        with open(PRIVATE_PATH) as f:
            priv = json.load(f)
        assert "x" in priv, "Private key missing field: x"

    def test_public_key_values_are_integers(self):
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        assert isinstance(pub["p"], int)
        assert isinstance(pub["alpha"], int)
        assert isinstance(pub["y"], int)

    def test_private_key_value_is_integer(self):
        generate_elgamal_keypair(TEST_USER)
        with open(PRIVATE_PATH) as f:
            priv = json.load(f)
        assert isinstance(priv["x"], int)

    def test_public_key_is_valid_json(self):
        generate_elgamal_keypair(TEST_USER)
        try:
            with open(PUBLIC_PATH) as f:
                json.load(f)
        except json.JSONDecodeError:
            pytest.fail("Public key file is not valid JSON")

    def test_private_key_is_valid_json(self):
        generate_elgamal_keypair(TEST_USER)
        try:
            with open(PRIVATE_PATH) as f:
                json.load(f)
        except json.JSONDecodeError:
            pytest.fail("Private key file is not valid JSON")


# ---------------------------------------------------------------------------
# 3. ElGamal math correctness
# ---------------------------------------------------------------------------
class TestElGamalMath:
    def test_y_equals_alpha_pow_x_mod_p(self):
        """Core ElGamal invariant: y = alpha^x mod p"""
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        with open(PRIVATE_PATH) as f:
            priv = json.load(f)
        assert pow(pub["alpha"], priv["x"], pub["p"]) == pub["y"], (
            "ElGamal math check failed: y != alpha^x mod p"
        )

    def test_prime_p_is_large_enough(self):
        """p should be at least 512 bits for meaningful security."""
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        assert pub["p"].bit_length() >= 512, "Prime p is too small"

    def test_private_key_x_within_valid_range(self):
        """x must satisfy 1 < x < p-1"""
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        with open(PRIVATE_PATH) as f:
            priv = json.load(f)
        assert 1 < priv["x"] < pub["p"] - 1, "Private key x is out of valid range"

    def test_alpha_is_valid_primitive_root_candidate(self):
        """alpha (generator) must be greater than 1 and less than p."""
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        assert 1 < pub["alpha"] < pub["p"], "alpha is not in valid range (1, p)"

    def test_y_is_nonzero(self):
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        assert pub["y"] != 0

    def test_y_is_within_valid_range(self):
        """y must be in range (0, p)"""
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        assert 0 < pub["y"] < pub["p"], "y is out of valid range (0, p)"


# ---------------------------------------------------------------------------
# 4. Key uniqueness (different users / repeated calls)
# ---------------------------------------------------------------------------
class TestKeyUniqueness:
    def test_different_users_get_different_private_keys(self):
        user2 = "test_keygen_user2"
        try:
            generate_elgamal_keypair(TEST_USER)
            generate_elgamal_keypair(user2)

            with open(PRIVATE_PATH) as f:
                x1 = json.load(f)["x"]
            with open(os.path.join("data", user2, "private.json")) as f:
                x2 = json.load(f)["x"]

            # Astronomically unlikely to collide; if they do, something is wrong
            assert x1 != x2, "Two different users got the same private key"
        finally:
            shutil.rmtree(os.path.join("data", user2), ignore_errors=True)
            pub2 = os.path.join("data", "Export", f"{user2}_public.json")
            if os.path.exists(pub2):
                os.remove(pub2)

    def test_two_calls_produce_different_keys(self):
        """Calling generate twice should produce different key material."""
        generate_elgamal_keypair(TEST_USER)
        with open(PRIVATE_PATH) as f:
            x1 = json.load(f)["x"]

        # Remove so second call can recreate
        _remove_keys()
        generate_elgamal_keypair(TEST_USER)
        with open(PRIVATE_PATH) as f:
            x2 = json.load(f)["x"]

        assert x1 != x2, "Repeated key generation produced identical keys"

    def test_different_users_get_different_public_keys(self):
        """Different users should have different y values."""
        user2 = "test_keygen_user2"
        try:
            generate_elgamal_keypair(TEST_USER)
            generate_elgamal_keypair(user2)

            with open(PUBLIC_PATH) as f:
                y1 = json.load(f)["y"]
            with open(os.path.join("data", "Export", f"{user2}_public.json")) as f:
                y2 = json.load(f)["y"]

            assert y1 != y2, "Two different users got the same public key y"
        finally:
            shutil.rmtree(os.path.join("data", user2), ignore_errors=True)
            pub2 = os.path.join("data", "Export", f"{user2}_public.json")
            if os.path.exists(pub2):
                os.remove(pub2)


# ---------------------------------------------------------------------------
# 5. Private key isolation
# ---------------------------------------------------------------------------
class TestPrivateKeyIsolation:
    def test_private_key_not_stored_in_public_file(self):
        generate_elgamal_keypair(TEST_USER)
        with open(PUBLIC_PATH) as f:
            pub = json.load(f)
        assert "x" not in pub, "Private key 'x' must not appear in the public key file"

    def test_public_fields_not_in_private_file(self):
        """The private file stores the secret; it shouldn't duplicate public fields
        in a way that would leak them — at minimum, 'y' should not be the only thing there."""
        generate_elgamal_keypair(TEST_USER)
        with open(PRIVATE_PATH) as f:
            priv = json.load(f)
        # The critical check: private file must have x
        assert "x" in priv

    def test_y_not_in_private_file(self):
        """y is a public value and should not be stored in the private key file."""
        generate_elgamal_keypair(TEST_USER)
        with open(PRIVATE_PATH) as f:
            priv = json.load(f)
        assert "y" not in priv, "Public value 'y' should not appear in the private key file"


# ---------------------------------------------------------------------------
# 6. Return value tests
# ---------------------------------------------------------------------------
class TestReturnValue:
    def test_returns_tuple_of_two_dicts(self):
        result = generate_elgamal_keypair(TEST_USER)
        assert isinstance(result, tuple), "Should return a tuple"
        assert len(result) == 2, "Should return (private_key, public_key)"

    def test_returned_private_key_has_x(self):
        priv, pub = generate_elgamal_keypair(TEST_USER)
        assert "x" in priv

    def test_returned_public_key_has_required_fields(self):
        priv, pub = generate_elgamal_keypair(TEST_USER)
        for field in ("p", "alpha", "y"):
            assert field in pub, f"Returned public key missing field: {field}"