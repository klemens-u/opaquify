# opaquify

Keep secret **values** out of sight, keep the file readable.

An opaquify env file looks and reads like a normal env file — names, comments
and non-secret config stay in plaintext. Only the values you sealed are
ciphertext:

```bash
# mail.env
MAIL_USER=klemens@example.com              # readable, as usual
MAIL_HOST=mail.example.com
MAIL_PASSWORD=age1:AGE....ciphertext....   # the only opaque line
```

At run time the sealed values are decrypted into the **environment of the
child process only** — never written to disk, never printed, never passed on
the command line (argv is visible in `ps`, shell history and agent
transcripts).

Crypto is [age](https://age-encryption.org) (X25519), called as a binary; no
Python dependencies.

## Install

```bash
# age: apt install age (Debian/Ubuntu) / brew install age (macOS)
curl -fsSL https://raw.githubusercontent.com/klemens-u/opaquify/main/opaquify \
  -o ~/.local/bin/opaquify && chmod +x ~/.local/bin/opaquify
```

No version pinning on purpose: `opaquify --version` tells you what you run.

## Usage

```bash
opaquify keygen                                # one key per user (0600)

printf 'super-geheim' | opaquify seal mail.env MAIL_PASSWORD

opaquify run mail.env -- himalaya envelope list "not flag seen"
opaquify run mail.env -- python3 send.py
```

Three commands, nothing else:

- `keygen` — creates `~/.local/state/opaquify/main.key` (one key per user)
- `seal <file> KEY` — encrypts a value (read from **stdin only**) into the
  file, writing `KEY=age1:<ciphertext>`; an existing line is replaced
- `run <file> -- <command...>` — decrypts the sealed values into the child
  process environment and runs the command; its exit code is passed through

## File format

- `KEY=...` lines; values starting with `age1:` are sealed
- everything else (comments, config, blank lines) is kept exactly as written
- a value wrapped in matching `"` or `'` is unwrapped
- minimal by design: no expansion, no conditionals, nothing shell-like

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `OPAQIFY_KEY_PATH` | key file path | `~/.local/state/opaquify/main.key` |
| `OPAQIFY_AGE_BIN` | age binary | `age` |
| `OPAQIFY_AGE_KEYGEN_BIN` | age-keygen binary | `age-keygen` |

The default key lives outside the data directory and carries no
secret-shaped name.

## Security model — honest

- Protects against **accidental** exposure: `cat`, log dumps, screenshots,
  agent turns that read files. A sealed file leaks nothing readable.
- The key is a same-user file: any process running as the same user can
  deliberately read it and decrypt. That trust boundary is not solved here —
  for that, put decryption behind a privileged helper or broker that exposes a
  narrow API instead of the key.
- There is **no tamper detection** (an earlier HMAC idea was dropped as
  unnecessary complexity): whoever can write the file can also change its
  readable config lines. If that matters, it is a broker-level concern.

## Tests

```bash
python3 -m pytest tests/        # requires age on PATH (or OPAQIFY_AGE_BIN)
```

End-to-end subprocess tests: version, the removed commands stay removed,
keygen, sealing + readability, run + env injection, exit-code propagation, a
clear error when the key is missing, key-path override.

## License

MIT
