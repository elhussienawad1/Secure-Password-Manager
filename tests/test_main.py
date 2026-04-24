"""
Tests for main.py: CLI menu flow.
Uses unittest.mock to simulate user input and verify the correct module
functions are called for each menu option.
"""

import os
import json
import shutil
import pytest
from unittest.mock import patch, call, MagicMock

import src.main as app


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TEST_USER = "test_main_user"
MASTER_PW = "MainTestPW!"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def cleanup():
    _clean()
    yield
    _clean()


def _clean():
    shutil.rmtree(os.path.join("data", TEST_USER), ignore_errors=True)
    pub = f"{TEST_USER}_public.json"
    if os.path.exists(pub):
        os.remove(pub)


def run_main_with_inputs(*inputs):
    """Patch builtins.input with the provided sequence and call main()."""
    with patch("builtins.input", side_effect=list(inputs)):
        with patch("builtins.print"):  # Suppress output during tests
            app.main()


# ---------------------------------------------------------------------------
# 1. Exit / basic navigation
# ---------------------------------------------------------------------------
class TestMenuNavigation:
    def test_exit_on_choice_0(self):
        """Choosing 0 immediately should exit without errors."""
        run_main_with_inputs(TEST_USER, "0")

    def test_invalid_choice_does_not_crash(self):
        run_main_with_inputs(TEST_USER, "99", "0")

    def test_multiple_invalid_choices_then_exit(self):
        run_main_with_inputs(TEST_USER, "abc", "!", "99", "0")


# ---------------------------------------------------------------------------
# 2. Option 1 — Initialize account
# ---------------------------------------------------------------------------
class TestInitializeAccount:
    def test_choice_1_calls_generate_elgamal_keypair(self):
        with patch("main.generate_elgamal_keypair") as mock_gen:
            with patch("builtins.input", side_effect=[TEST_USER, "1", "0"]):
                with patch("builtins.print"):
                    app.main()
            mock_gen.assert_called_once_with(TEST_USER)

    def test_choice_1_skips_if_already_initialized(self):
        """If private.json already exists, generate should NOT be called again."""
        os.makedirs(os.path.join("data", TEST_USER), exist_ok=True)
        with open(os.path.join("data", TEST_USER, "private.json"), "w") as f:
            json.dump({"x": 12345}, f)

        with patch("main.generate_elgamal_keypair") as mock_gen:
            with patch("builtins.input", side_effect=[TEST_USER, "1", "0"]):
                with patch("builtins.print"):
                    app.main()
            mock_gen.assert_not_called()

    def test_choice_1_requires_key_json(self):
        """If key.json is missing, option 1 should raise FileNotFoundError."""
        with patch("os.path.exists", side_effect=lambda p: False if p == "key.json" else os.path.exists.__wrapped__(p) if hasattr(os.path.exists, "__wrapped__") else True):
            # This is a tricky mock — alternatively just test the real behavior
            pass  # Covered by integration test below

    def test_choice_1_key_json_missing_raises(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # No key.json in temp dir
        with patch("builtins.input", side_effect=[TEST_USER, "1", "0"]):
            with patch("builtins.print"):
                with pytest.raises(FileNotFoundError):
                    app.main()


# ---------------------------------------------------------------------------
# 3. Option 2 — Add credential
# ---------------------------------------------------------------------------
class TestAddCredentialMenu:
    def test_choice_2_calls_add_credential(self):
        with patch("main.add_credential") as mock_add:
            inputs = [TEST_USER, "2", MASTER_PW, "example.com", "alice", "pw123", "0"]
            with patch("builtins.input", side_effect=inputs):
                with patch("builtins.print"):
                    app.main()
            mock_add.assert_called_once_with(TEST_USER, MASTER_PW, "example.com", "alice", "pw123")

    def test_choice_2_passes_correct_arguments(self):
        with patch("main.add_credential") as mock_add:
            inputs = [TEST_USER, "2", "secret_pw", "github.com", "bob", "gh_token", "0"]
            with patch("builtins.input", side_effect=inputs):
                with patch("builtins.print"):
                    app.main()
            args = mock_add.call_args[0]
            assert args[0] == TEST_USER
            assert args[1] == "secret_pw"
            assert args[2] == "github.com"
            assert args[3] == "bob"
            assert args[4] == "gh_token"


# ---------------------------------------------------------------------------
# 4. Option 3 — Retrieve credential
# ---------------------------------------------------------------------------
class TestRetrieveCredentialMenu:
    def test_choice_3_calls_retrieve_credential(self):
        with patch("main.retrieve_credential") as mock_ret:
            inputs = [TEST_USER, "3", MASTER_PW, "example.com", "0"]
            with patch("builtins.input", side_effect=inputs):
                with patch("builtins.print"):
                    app.main()
            mock_ret.assert_called_once_with(TEST_USER, MASTER_PW, "example.com")


# ---------------------------------------------------------------------------
# 5. Option 4 — Update credential
# ---------------------------------------------------------------------------
class TestUpdateCredentialMenu:
    def test_choice_4_calls_update_credential(self):
        with patch("main.update_credential") as mock_upd:
            inputs = [TEST_USER, "4", MASTER_PW, "example.com", "new_user", "new_pw", "0"]
            with patch("builtins.input", side_effect=inputs):
                with patch("builtins.print"):
                    app.main()
            mock_upd.assert_called_once_with(
                TEST_USER, MASTER_PW, "example.com", "new_user", "new_pw"
            )

    def test_choice_4_passes_empty_strings_when_fields_blank(self):
        with patch("main.update_credential") as mock_upd:
            inputs = [TEST_USER, "4", MASTER_PW, "example.com", "", "", "0"]
            with patch("builtins.input", side_effect=inputs):
                with patch("builtins.print"):
                    app.main()
            args = mock_upd.call_args[0]
            assert args[3] == ""   # new_user blank
            assert args[4] == ""   # new_password blank


# ---------------------------------------------------------------------------
# 6. Option 5 — Delete credential
# ---------------------------------------------------------------------------
class TestDeleteCredentialMenu:
    def test_choice_5_calls_delete_credential(self):
        with patch("main.delete_credential") as mock_del:
            inputs = [TEST_USER, "5", MASTER_PW, "example.com", "0"]
            with patch("builtins.input", side_effect=inputs):
                with patch("builtins.print"):
                    app.main()
            mock_del.assert_called_once_with(TEST_USER, MASTER_PW, "example.com")


# ---------------------------------------------------------------------------
# 7. Option 6 — List credentials
# ---------------------------------------------------------------------------
class TestListCredentialsMenu:
    def test_choice_6_calls_list_credentials(self):
        with patch("main.list_credentials") as mock_list:
            inputs = [TEST_USER, "6", MASTER_PW, "0"]
            with patch("builtins.input", side_effect=inputs):
                with patch("builtins.print"):
                    app.main()
            mock_list.assert_called_once_with(TEST_USER, MASTER_PW)


# ---------------------------------------------------------------------------
# 8. Option 7 — Verify vault integrity
# ---------------------------------------------------------------------------
class TestVerifyVaultMenu:
    def test_choice_7_requires_private_key(self, capsys):
        """If private.json is missing, option 7 should print an error, not crash."""
        with patch("builtins.input", side_effect=[TEST_USER, "7", "0"]):
            app.main()
        captured = capsys.readouterr()
        assert "initialize" in captured.out.lower() or "not found" in captured.out.lower()

    def test_choice_7_requires_vault_file(self, capsys):
        """If vault doesn't exist, option 7 should print a helpful message."""
        os.makedirs(os.path.join("data", TEST_USER), exist_ok=True)
        with open(os.path.join("data", TEST_USER, "private.json"), "w") as f:
            json.dump({"x": 12345}, f)

        with patch("builtins.input", side_effect=[TEST_USER, "7", "0"]):
            app.main()
        captured = capsys.readouterr()
        assert "vault" in captured.out.lower() or "credential" in captured.out.lower()

    def test_choice_7_calls_verify_vault_and_reports_valid(self, capsys):
        with patch("main.verify_vault", return_value=True) as mock_verify:
            # Set up the necessary files so the guard checks pass
            os.makedirs(os.path.join("data", TEST_USER), exist_ok=True)
            with open(os.path.join("data", TEST_USER, "private.json"), "w") as f:
                json.dump({"x": 99}, f)
            vault_data = {
                "encrypted_vault": "abc123",
                "signature": "111:222"
            }
            with open(os.path.join("data", TEST_USER, "vault.json"), "w") as f:
                json.dump(vault_data, f)

            with patch("builtins.input", side_effect=[TEST_USER, "7", "0"]):
                app.main()

        captured = capsys.readouterr()
        assert "verified" in captured.out.lower() or "valid" in captured.out.lower()

    def test_choice_7_reports_tampering_when_verify_fails(self, capsys):
        with patch("main.verify_vault", return_value=False):
            os.makedirs(os.path.join("data", TEST_USER), exist_ok=True)
            with open(os.path.join("data", TEST_USER, "private.json"), "w") as f:
                json.dump({"x": 99}, f)
            vault_data = {
                "encrypted_vault": "abc123",
                "signature": "111:222"
            }
            with open(os.path.join("data", TEST_USER, "vault.json"), "w") as f:
                json.dump(vault_data, f)

            with patch("builtins.input", side_effect=[TEST_USER, "7", "0"]):
                app.main()

        captured = capsys.readouterr()
        assert (
            "failed" in captured.out.lower()
            or "tamper" in captured.out.lower()
            or "alert" in captured.out.lower()
        )


# ---------------------------------------------------------------------------
# 9. Option 8 — Export vault
# ---------------------------------------------------------------------------
class TestExportVaultMenu:
    def test_choice_8_calls_export_vault_when_recipient_key_exists(self):
        recipient = "recipient_user"
        try:
            # Create a fake recipient public key file
            with open(f"{recipient}_public.json", "w") as f:
                json.dump({"p": 23, "alpha": 5, "y": 10}, f)

            with patch("main.export_vault") as mock_export:
                inputs = [TEST_USER, "8", MASTER_PW, recipient, "0"]
                with patch("builtins.input", side_effect=inputs):
                    with patch("builtins.print"):
                        app.main()
                mock_export.assert_called_once_with(TEST_USER, MASTER_PW, recipient)
        finally:
            if os.path.exists(f"{recipient}_public.json"):
                os.remove(f"{recipient}_public.json")

    def test_choice_8_aborts_when_recipient_key_missing(self, capsys):
        with patch("builtins.input", side_effect=[TEST_USER, "8", MASTER_PW, "ghost_user", "0"]):
            app.main()
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "public key" in captured.out.lower()