"""
conftest.py — shared pytest fixtures and project-wide test configuration.

Place this file in the same directory as your test files (tests/) or
in the project root so pytest picks it up automatically.
"""

import os
import sys
import json
import shutil
import pytest

# ---------------------------------------------------------------------------
# Make sure the project root is on sys.path so all modules are importable.
# Adjust the path if your tests/ folder is nested differently.
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Minimal key.json guard
# ---------------------------------------------------------------------------
KEY_JSON = os.path.join(PROJECT_ROOT, "key.json")

@pytest.fixture(scope="session", autouse=True)
def ensure_key_json():
    """
    Make sure key.json exists for the test session.
    If it is missing, create a minimal one with safe 512-bit parameters
    so that key generation tests don't immediately fail on a missing config.

    !! Replace these sample values with your project's actual parameters !!
    """
    if not os.path.exists(KEY_JSON):
        # Safe 512-bit Sophie-Germain prime and a primitive root.
        # These are example values — replace with parameters from your spec.
        params = {
            "p": int(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
                "FFFFFFFFFFFFFFFF", 16
            ),
            "alpha": 2,
            # DH params (may be same as ElGamal params)
            "q": int(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
                "FFFFFFFFFFFFFFFF", 16
            ),
            "g": 2,
        }
        with open(KEY_JSON, "w") as f:
            json.dump(params, f, indent=2)
        created = True
    else:
        created = False

    yield

    if created and os.path.exists(KEY_JSON):
        os.remove(KEY_JSON)


# ---------------------------------------------------------------------------
# Shared user cleanup helper (available to all test modules)
# ---------------------------------------------------------------------------
def remove_user(username: str):
    """Delete all files created for a test user."""
    shutil.rmtree(os.path.join(PROJECT_ROOT, "data", username), ignore_errors=True)
    pub = os.path.join(PROJECT_ROOT, f"{username}_public.json")
    if os.path.exists(pub):
        os.remove(pub)


@pytest.fixture
def clean_user(request):
    """
    Parameterised fixture: create + clean up a named test user.
    Usage in a test:
        def test_something(clean_user):
            username = clean_user("my_test_user")
    """
    created = []

    def _factory(username):
        remove_user(username)
        created.append(username)
        return username

    yield _factory

    for u in created:
        remove_user(u)