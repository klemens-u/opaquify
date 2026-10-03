# opaquify

Keep secret **values** out of sight, keep the file readable.

An opaquify env file looks and reads like a normal env file — names, comments
and non-secret config stay in plaintext. Only the lines you sealed are
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

Crypto is [age](https://age-encryption.org) (X25519), augmented with an
HMAC-SHA256 over the plaintext lines so tampering with readable config stays
detectable (the gap dotenv-style tools have).

## Install

`opaquify` is a single Python 3 (>= 3.10) script, no dependencies. It shells
out to the `age` binary:

```bash
# Debian/Ubuntu
apt install age

# macOS
brew install age
```

Put `opaquify` on your PATH (or call it by path).

## Usage

```bash
opaquify keygen mail                                 # create key (0600)

printf 'super-geheim' | opaquify seal mail.env MAIL_PASSWORD   # seal one value
opaquify verify mail.env                             # MAC check

# run any program with the decrypted env
opaquify run mail.env -- himalaya envelope list "not flag seen"
opaquify run mail.env -- python3 send.py
```

- Values for `seal` come from **stdin only**, never from argv.
- `run` picks the key from the file name (`mail.env` -> `mail.key`).

## File format

- `KEY=...` lines; values starting with `age1:` are sealed (age-encrypted,
  base64, single line).
- Other lines (comments, config values) are kept verbatim.
- `# opaquify-mac: <hex>` — HMAC-SHA256 over all other lines; `verify` checks
  it. After manual edits, re-seal the touched line to refresh the MAC.
- Quoting: a value wrapped in matching `"` or `'` is stripped.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `OPAQIFY_KEY_PATH` | key file path | `~/.local/state/opaquify/<name>.key` |
| `OPAQIFY_AGE_BIN` | age binary | `age` |
| `OPAQIFY_AGE_KEYGEN_BIN` | age-keygen binary | `age-keygen` |

The default key location is deliberately outside the data directory and away
from obvious secret-shaped names.

## Security model — honest

- Protects against **accidental** exposure: `cat`, log dumps, screenshots,
  agent turns that read files. A sealed file leaks nothing readable.
- The key is a same-user file: any process running as the same user could
  deliberately read it and decrypt. That trust boundary is not solved here —
  for that, run the decryption behind a privileged helper or broker service
  that exposes a narrow API instead of the key.

## Tests

```bash
python3 -m pytest tests/        # requires age on PATH (or OPAQIFY_AGE_BIN)
```

End-to-end subprocess tests: keygen, seal/readability, run + env injection,
exit-code propagation, MAC tamper detection, env-path override.

## License

MIT