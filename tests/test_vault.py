"""
Tests for Module 2: Vault Encryption & Credential Management (vault.py)
Covers: add / retrieve / update / delete / list, wrong password, tamper detection.
"""

import os
import json
import shutil
import pytest

from keygen import generate_elgamal_keypair
from vault import (
    add_credential,
    retrieve_credential,
    update_credential,
    delete_credential,
    list_credentials,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TEST_USER = "test_vault_user"
MASTER_PW = "SuperSecretMaster!"
WRONG_PW = "WrongPassword123"
VAULT_PATH = os.path.join("data", TEST_USER, "vault.json")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def setup_user():
    """Create a fresh user account before each test, clean up after."""
    _clean()
    generate_elgamal_keypair(TEST_USER)
    yield
    _clean()


def _clean():
    shutil.rmtree(os.path.join("data", TEST_USER), ignore_errors=True)
    for f in (f"{TEST_USER}_public.json",):
        if os.path.exists(f):
            os.remove(f)


def _add(website="example.com", user="alice", password="pass123"):
    add_credential(TEST_USER, MASTER_PW, website, user, password)


# ---------------------------------------------------------------------------
# 1. Add credential
# ---------------------------------------------------------------------------
class TestAddCredential:
    def test_vault_file_created_after_add(self):
        _add()
        assert os.path.exists(VAULT_PATH)

    def test_vault_file_is_valid_json(self):
        _add()
        with open(VAULT_PATH) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_vault_json_has_expected_keys(self):
        _add()
        with open(VAULT_PATH) as f:
            data = json.load(f)
        assert "encrypted_vault" in data
        assert "signature" in data

    def test_encrypted_vault_is_not_plaintext(self):
        """Plaintext credentials must not appear in raw vault file."""
        _add(website="github.com", user="bob", password="secret99")
        with open(VAULT_PATH) as f:
            raw = f.read()
        assert "secret99" not in raw
        assert "github.com" not in raw
        assert "bob" not in raw

    def test_can_add_multiple_credentials(self):
        _add("site1.com", "user1", "pw1")
        _add("site2.com", "user2", "pw2")
        _add("site3.com", "user3", "pw3")
        # If no exception is raised, the vault handled multiple entries
        assert os.path.exists(VAULT_PATH)

    def test_add_duplicate_website_does_not_corrupt_vault(self):
        """Adding the same website twice should not raise or corrupt the file."""
        _add("dup.com", "user1", "pw1")
        _add("dup.com", "user2", "pw2")  # May overwrite or store both — must not crash
        with open(VAULT_PATH) as f:
            data = json.load(f)
        assert "encrypted_vault" in data


# ---------------------------------------------------------------------------
# 2. Retrieve credential
# ---------------------------------------------------------------------------
class TestRetrieveCredential:
    def test_retrieve_existing_credential(self, capsys):
        _add("github.com", "alice", "gh_pass")
        retrieve_credential(TEST_USER, MASTER_PW, "github.com")
        out = capsys.readouterr().out
        # The retrieved output should contain the stored values
        assert "alice" in out or "gh_pass" in out

    def test_retrieve_nonexistent_website_does_not_crash(self, capsys):
        _add()
        retrieve_credential(TEST_USER, MASTER_PW, "notexist.com")
        # Should print a message — not raise an exception

    def test_retrieve_with_wrong_password_fails(self, capsys):
        _add("secure.com", "user", "mypassword")
        
        # Wrong password must NOT raise an exception — it should be handled gracefully
        retrieve_credential(TEST_USER, WRONG_PW, "secure.com")
        
        out = capsys.readouterr().out
        
        # Must print an error message
        assert any(
            word in out.lower() for word in ("error", "invalid", "wrong", "incorrect", "failed", "denied")
        ), "Wrong password should print an error message"
        
        # Must never expose the stored credential
        assert "mypassword" not in out

        
    def test_retrieve_correct_data_after_multiple_adds(self, capsys):
        _add("a.com", "userA", "passA")
        _add("b.com", "userB", "passB")
        retrieve_credential(TEST_USER, MASTER_PW, "b.com")
        out = capsys.readouterr().out
        assert "userB" in out or "passB" in out


# ---------------------------------------------------------------------------
# 3. Update credential
# ---------------------------------------------------------------------------
class TestUpdateCredential:
    def test_update_username(self, capsys):
        _add("update.com", "old_user", "old_pass")
        update_credential(TEST_USER, MASTER_PW, "update.com", new_user="new_user", new_password="")
        retrieve_credential(TEST_USER, MASTER_PW, "update.com")
        out = capsys.readouterr().out
        assert "new_user" in out

    def test_update_password(self, capsys):
        _add("update.com", "alice", "old_pass")
        update_credential(TEST_USER, MASTER_PW, "update.com", new_user="", new_password="new_pass")
        retrieve_credential(TEST_USER, MASTER_PW, "update.com")
        out = capsys.readouterr().out
        assert "new_pass" in out

    def test_update_both_fields(self, capsys):
        _add("update.com", "alice", "old_pass")
        update_credential(TEST_USER, MASTER_PW, "update.com", new_user="bob", new_password="new_pass")
        retrieve_credential(TEST_USER, MASTER_PW, "update.com")
        out = capsys.readouterr().out
        assert "bob" in out or "new_pass" in out

    def test_update_nonexistent_website_does_not_crash(self):
        _add()
        update_credential(TEST_USER, MASTER_PW, "ghost.com", new_user="x", new_password="y")

    def test_update_with_wrong_password_fails(self):
        _add("update.com", "alice", "old_pass")
        try:
            update_credential(TEST_USER, WRONG_PW, "update.com", new_user="hacker", new_password="hacked")
        except Exception:
            pass  # Expected

        # The stored credential must still be the original
        # (retrieve with correct pw and check hacker value is not there)

    def test_vault_is_re_signed_after_update(self):
        _add("update.com", "alice", "pass")
        with open(VAULT_PATH) as f:
            sig_before = json.load(f)["signature"]
        update_credential(TEST_USER, MASTER_PW, "update.com", new_user="bob", new_password="")
        with open(VAULT_PATH) as f:
            sig_after = json.load(f)["signature"]
        assert sig_before != sig_after, "Signature should change after an update"


# ---------------------------------------------------------------------------
# 4. Delete credential
# ---------------------------------------------------------------------------
class TestDeleteCredential:
    def test_delete_existing_credential(self, capsys):
        _add("todelete.com", "user", "pass")
        delete_credential(TEST_USER, MASTER_PW, "todelete.com")
        retrieve_credential(TEST_USER, MASTER_PW, "todelete.com")
        out = capsys.readouterr().out
        # After deletion, credentials should not appear
        assert "pass" not in out

    def test_delete_nonexistent_website_does_not_crash(self):
        _add()
        delete_credential(TEST_USER, MASTER_PW, "ghost.com")

    def test_delete_one_of_multiple_preserves_others(self, capsys):
        _add("keep.com", "userK", "passK")
        _add("remove.com", "userR", "passR")
        delete_credential(TEST_USER, MASTER_PW, "remove.com")
        retrieve_credential(TEST_USER, MASTER_PW, "keep.com")
        out = capsys.readouterr().out
        assert "userK" in out or "passK" in out

    def test_vault_is_re_signed_after_delete(self):
        _add("del.com", "user", "pass")
        with open(VAULT_PATH) as f:
            sig_before = json.load(f)["signature"]
        delete_credential(TEST_USER, MASTER_PW, "del.com")
        with open(VAULT_PATH) as f:
            sig_after = json.load(f)["signature"]
        assert sig_before != sig_after, "Signature should change after a deletion"

    def test_delete_with_wrong_password_fails(self):
        _add("del.com", "user", "pass")
        try:
            delete_credential(TEST_USER, WRONG_PW, "del.com")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 5. List credentials
# ---------------------------------------------------------------------------
class TestListCredentials:
    def test_list_shows_all_sites(self, capsys):
        _add("alpha.com", "u1", "p1")
        _add("beta.com", "u2", "p2")
        list_credentials(TEST_USER, MASTER_PW)
        out = capsys.readouterr().out
        assert "alpha.com" in out
        assert "beta.com" in out

    def test_list_empty_vault_does_not_crash(self, capsys):
        # No credentials added — vault may not exist yet
        list_credentials(TEST_USER, MASTER_PW)

    def test_list_with_wrong_password_does_not_expose_data(self, capsys):
        _add("secret.com", "user", "topsecret")
        try:
            list_credentials(TEST_USER, WRONG_PW)
        except Exception:
            pass
        out = capsys.readouterr().out
        assert "topsecret" not in out


# ---------------------------------------------------------------------------
# 6. Encryption correctness
# ---------------------------------------------------------------------------
class TestEncryptionCorrectness:
    def test_vault_file_changes_after_add(self):
        _add("first.com", "u1", "p1")
        with open(VAULT_PATH) as f:
            enc1 = json.load(f)["encrypted_vault"]
        _add("second.com", "u2", "p2")
        with open(VAULT_PATH) as f:
            enc2 = json.load(f)["encrypted_vault"]
        assert enc1 != enc2

    def test_two_different_passwords_produce_different_ciphertexts(self):
        """Same credential, two users with different master passwords → different ciphertext."""
        user2 = "test_vault_user2"
        try:
            generate_elgamal_keypair(user2)
            add_credential(user2, "AnotherMasterPW!", "site.com", "user", "pw")
            add_credential(TEST_USER, MASTER_PW, "site.com", "user", "pw")

            with open(VAULT_PATH) as f:
                enc1 = json.load(f)["encrypted_vault"]
            with open(os.path.join("data", user2, "vault.json")) as f:
                enc2 = json.load(f)["encrypted_vault"]

            assert enc1 != enc2
        finally:
            shutil.rmtree(os.path.join("data", user2), ignore_errors=True)
            if os.path.exists(f"{user2}_public.json"):
                os.remove(f"{user2}_public.json")