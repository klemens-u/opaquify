"""KISS end-to-end tests: run the real script against a throwaway key.

The suite needs `age` + `age-keygen` on PATH (or OPAQIFY_AGE_BIN /
OPAQIFY_AGE_KEYGEN_BIN pointing at them). It is pure-subprocess: no mocks.
"""
import os
import shutil
import stat
import subprocess
import sys

import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "opaquify")
SECRET = "supergeheim-123"


def run(tmp_path, *args, stdin=None, env=None):
    e = dict(os.environ)
    e["XDG_STATE_HOME"] = str(tmp_path / "state")     # hermetic default dir
    e.update(env or {})
    return subprocess.run(
        [sys.executable, SCRIPT, *args], input=stdin,
        capture_output=True, text=True, env=e)


@pytest.fixture(scope="module")
def have_age():
    if not (shutil.which("age") and shutil.which("age-keygen")):
        pytest.skip("age/age-keygen not on PATH (set OPAQIFY_AGE_BIN)")
    return True


@pytest.fixture()
def key(tmp_path, have_age):
    r = run(tmp_path, "keygen", "mail")
    assert r.returncode == 0, r.stderr
    yield str(tmp_path / "state" / "opaquify" / "mail.key")


def test_keygen_file_is_600_and_prints_pubkey(tmp_path, have_age):
    r = run(tmp_path, "keygen", "mail")
    assert r.returncode == 0, r.stderr
    p = tmp_path / "state" / "opaquify" / "mail.key"
    assert p.exists()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert "public key: age1" in r.stdout


def test_keygen_refuses_to_overwrite(tmp_path, key):
    r = run(tmp_path, "keygen", "mail")
    assert r.returncode != 0
    assert "already exists" in r.stderr


def test_seal_keeps_file_readable_and_hides_secret(tmp_path, key):
    env = tmp_path / "mail.env"
    open(env, "w").write(   # a normal env file first
        "MAIL_USER=klemens@example.com\nMAIL_HOST=mail.example.com\n")
    r = run(tmp_path, "seal", str(env), "MAIL_PASSWORD", stdin=SECRET)
    assert r.returncode == 0, r.stderr
    body = env.read_text()
    # sealed value, no plaintext secret anywhere, MAC present
    assert "MAIL_PASSWORD=age1:" in body
    assert SECRET not in body
    assert "# opaquify-mac:" in body
    # config lines stay readable
    assert "MAIL_USER=klemens@example.com" in body
    assert "MAIL_HOST=mail.example.com" in body
    # sealing an EXISTING line replaces it (plaintext -> sealed)
    r = run(tmp_path, "seal", str(env), "MAIL_USER",
            stdin="klemens@other.example")
    assert r.returncode == 0, r.stderr
    body = env.read_text()
    assert "MAIL_USER=age1:" in body
    assert "klemens@other.example" not in body
    assert SECRET not in body


def test_run_injects_decrypted_env_and_propagates_exit(tmp_path, key):
    env = tmp_path / "mail.env"
    open(env, "w").write(f"MAIL_USER=klemens@example.com\n")
    run(tmp_path, "seal", str(env), "MAIL_PASSWORD", stdin=SECRET)
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import os,sys\n"
        "pw=os.environ['MAIL_PASSWORD']\n"
        "assert pw==%r, pw\n"
        "print('ok user=' + os.environ['MAIL_USER'])\n"
        "sys.exit(7)\n" % SECRET)
    r = run(tmp_path, "run", str(env), "--", sys.executable, str(probe))
    assert r.returncode == 7            # child exit code passes through
    assert "ok user=klemens@example.com" in r.stdout
    assert SECRET not in r.stdout       # and nothing else leaked


def test_run_key_derives_from_filename(tmp_path, have_age):
    """mail.env -> mail.key without extra arguments."""
    run(tmp_path, "keygen", "mail")
    env = tmp_path / "mail.env"
    open(env, "w").write("A=1\nB=2\n")
    r = run(tmp_path, "run", str(env), "--", "env")
    assert r.returncode == 0
    assert "A=1" in r.stdout and "B=2" in r.stdout


def test_opaqify_key_path_override_wins(tmp_path, have_age):
    kp = tmp_path / "elsewhere" / "mykey"
    r = run(tmp_path, "keygen", "mail", env={"OPAQIFY_KEY_PATH": str(kp)})
    assert r.returncode == 0, r.stderr
    assert kp.exists()
    env = tmp_path / "x.env"
    open(env, "w").write("")
    r = run(tmp_path, "seal", str(env), "TOK", stdin="abc",
            env={"OPAQIFY_KEY_PATH": str(kp)})
    assert r.returncode == 0, r.stderr
    assert "TOK=age1:" in env.read_text()


def test_verify_catches_plaintext_tampering(tmp_path, key):
    env = tmp_path / "mail.env"
    open(env, "w").write("MAIL_HOST=mail.example.com\n")
    run(tmp_path, "seal", str(env), "MAIL_PASSWORD", stdin=SECRET)
    r = run(tmp_path, "verify", str(env))
    assert r.returncode == 0 and "ok" in r.stdout
    open(env, "a").write("MAIL_HOST=evil.example.com\n")   # tamper
    r = run(tmp_path, "verify", str(env))
    assert r.returncode != 0
    assert "MAC mismatch" in r.stderr


def test_run_missing_key_is_a_clear_error_not_silent(tmp_path, have_age):
    env = tmp_path / "mail.env"
    open(env, "w").write("MAIL_PASSWORD=age1:AAAA\n")
    r = run(tmp_path, "run", str(env), "--", "env")
    assert r.returncode != 0
    assert "key not found" in r.stderr.lower() or "decrypt" in r.stderr.lower()