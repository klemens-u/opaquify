"""KISS end-to-end tests: run the real script against a throwaway key.

Needs `age` + `age-keygen` on PATH (or OPAQIFY_AGE_BIN / OPAQIFY_AGE_KEYGEN_BIN).
Pure subprocess, no mocks, no import of the script.
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
    e["XDG_STATE_HOME"] = str(tmp_path / "state")       # hermetic default dir
    e.update(env or {})
    return subprocess.run([sys.executable, SCRIPT, *args], input=stdin,
                          capture_output=True, text=True, env=e)


@pytest.fixture(scope="module")
def have_age():
    if not (shutil.which("age") and shutil.which("age-keygen")):
        pytest.skip("age/age-keygen not on PATH (set OPAQIFY_AGE_BIN)")
    return True


@pytest.fixture()
def key(tmp_path, have_age):
    r = run(tmp_path, "keygen")
    assert r.returncode == 0, r.stderr
    return tmp_path / "state" / "opaquify" / "main.key"


def test_version(tmp_path):
    r = run(tmp_path, "--version")
    assert r.returncode == 0
    assert r.stdout.startswith("opaquify ")


def test_no_show_or_verify_command(tmp_path, key):
    """The stripped surface must really be gone (KISS contract)."""
    for cmd in ("show", "verify"):
        r = run(tmp_path, cmd, "x.env", "KEY")
        assert r.returncode == 2
        assert "unknown command" in r.stderr


def test_keygen_creates_main_key_600(tmp_path, have_age):
    r = run(tmp_path, "keygen")
    assert r.returncode == 0, r.stderr
    p = tmp_path / "state" / "opaquify" / "main.key"
    assert p.exists()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert "public key: age1" in r.stdout


def test_keygen_refuses_to_overwrite(tmp_path, key):
    r = run(tmp_path, "keygen")
    assert r.returncode != 0
    assert "already exists" in r.stderr


def test_seal_keeps_config_readable_and_hides_secret(tmp_path, key):
    env = tmp_path / "mail.env"
    open(env, "w").write(
        "# mail connector\nMAIL_USER=klemens@example.com\nMAIL_HOST=mail.example.com\n")
    r = run(tmp_path, "seal", str(env), "MAIL_PASSWORD", stdin=SECRET)
    assert r.returncode == 0, r.stderr
    body = env.read_text()
    assert "MAIL_PASSWORD=age1:" in body          # sealed
    assert SECRET not in body                     # no plaintext secret
    assert "MAIL_USER=klemens@example.com" in body   # config readable
    assert "MAIL_HOST=mail.example.com" in body
    assert "# mail connector" in body                # comments survive
    # sealing an existing line replaces it
    r = run(tmp_path, "seal", str(env), "MAIL_USER", stdin="other@example.com")
    assert r.returncode == 0, r.stderr
    body = env.read_text()
    assert "MAIL_USER=age1:" in body
    assert "other@example.com" not in body
    assert SECRET not in body


def test_run_injects_env_and_propagates_exit(tmp_path, key):
    env = tmp_path / "mail.env"
    open(env, "w").write("MAIL_USER=klemens@example.com\n")
    run(tmp_path, "seal", str(env), "MAIL_PASSWORD", stdin=SECRET)
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import os, sys\n"
        "assert os.environ['MAIL_PASSWORD'] == %r\n"
        "print('ok user=' + os.environ['MAIL_USER'])\n"
        "sys.exit(7)\n" % SECRET)
    r = run(tmp_path, "run", str(env), "--", sys.executable, str(probe))
    assert r.returncode == 7                       # child exit code passes through
    assert "ok user=klemens@example.com" in r.stdout
    assert SECRET not in r.stdout                  # nothing leaked


def test_run_works_for_plain_and_sealed_lines(tmp_path, key):
    env = tmp_path / "x.env"
    open(env, "w").write("PLAIN=hello\n")
    run(tmp_path, "seal", str(env), "SEALED", stdin="world")
    r = run(tmp_path, "run", str(env), "--", "env")
    assert r.returncode == 0
    assert "PLAIN=hello" in r.stdout and "SEALED=world" in r.stdout


def test_missing_key_is_a_clear_error(tmp_path, have_age):
    env = tmp_path / "mail.env"
    open(env, "w").write("A=1\n")
    r = run(tmp_path, "run", str(env), "--", "true")
    assert r.returncode != 0
    assert "key not found" in r.stderr
    assert "keygen" in r.stderr                    # tells you what to do


def test_env_key_path_override(tmp_path, have_age):
    kp = tmp_path / "elsewhere" / "custom.key"
    e = {"OPAQIFY_KEY_PATH": str(kp)}
    r = run(tmp_path, "keygen", env=e)
    assert r.returncode == 0, r.stderr
    assert kp.exists()
    assert not (tmp_path / "state" / "opaquify" / "main.key").exists()
    env = tmp_path / "x.env"
    env.write_text("A=1\n")            # existing file: seal replaces in place
    r = run(tmp_path, "seal", str(env), "TOK", stdin="abc", env=e)
    assert r.returncode == 0, r.stderr
    assert "TOK=age1:" in env.read_text()


def test_seal_refuses_to_create_a_bare_file(tmp_path, key):
    """A typo in the path must not silently produce a one-line env file."""
    missing = tmp_path / "typo.env"
    r = run(tmp_path, "seal", str(missing), "TOK", stdin="x")
    assert r.returncode != 0
    assert "refusing to write" in r.stderr
    assert not missing.exists()
    # an existing file with only comments counts as empty too
    only_comments = tmp_path / "comments.env"
    only_comments.write_text("# nothing here yet\n\n")
    r = run(tmp_path, "seal", str(only_comments), "TOK", stdin="x")
    assert r.returncode != 0
    assert only_comments.read_text() == "# nothing here yet\n\n"   # untouched


def test_seal_create_can_be_opted_into(tmp_path, key):
    fresh = tmp_path / "new.env"
    r = run(tmp_path, "seal", str(fresh), "TOK", stdin="x", env={"OPAQIFY_SEAL_CREATE": "1"})
    assert r.returncode == 0, r.stderr
    assert "TOK=age1:" in fresh.read_text()
