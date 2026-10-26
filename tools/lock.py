"""Encrypt speech pages for the public site.

The passphrase is read from the macOS Keychain (service "speeches-site"),
never from a file or argument. Each page is encrypted with AES-256-GCM using
a key derived from the passphrase with Argon2id, and wrapped in a small
unlock page that decrypts it in the browser.
"""
import argparse
import base64
import html
import json
import os
import subprocess
import sys
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
ARGON2 = ROOT / "vendor" / "package" / "dist" / "argon2.umd.min.js"
TEMPLATE = ROOT / "tools" / "unlock.html"
SITE = ROOT / "docs"

KDF = {"iterations": 3, "memorySize": 65536, "parallelism": 1, "hashLength": 32}


def passphrase():
    out = subprocess.run(
        ["security", "find-generic-password", "-s", os.environ.get("SPEECHES_KEYCHAIN_SERVICE", "speeches-site"), "-w"],
        capture_output=True, text=True,
    )
    if out.returncode != 0 or not out.stdout.strip():
        sys.exit("No passphrase in the Keychain under service 'speeches-site'.")
    return out.stdout.rstrip("\n")


def encrypt(plaintext, secret):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hash_secret_raw(
        secret.encode(), salt,
        time_cost=KDF["iterations"], memory_cost=KDF["memorySize"],
        parallelism=KDF["parallelism"], hash_len=KDF["hashLength"], type=Type.ID,
    )
    sealed = AESGCM(key).encrypt(nonce, plaintext, None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"salt": b64(salt), "nonce": b64(nonce), "data": b64(sealed), "kdf": KDF}


def build_page(title, payload):
    page = TEMPLATE.read_text()
    page = page.replace("{{TITLE}}", html.escape(title))
    page = page.replace("{{ARGON2}}", ARGON2.read_text())
    page = page.replace("{{PAYLOAD}}", json.dumps(payload))
    return page


def build_index(entries):
    items = "\n".join(
        f'    <li><a href="{slug}/">{html.escape(title)}</a></li>' for slug, title in entries
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Speeches</title>
<style>
  body {{ margin: 0; background: #171310; color: #ece4d8; font: 17px/1.5 Georgia, serif; }}
  main {{ max-width: 520px; margin: 0 auto; padding: 48px 20px; }}
  h1 {{ font-weight: 600; font-size: 30px; margin: 0 0 20px; }}
  a {{ color: #8fd0ad; }}
  li {{ margin: 8px 0; }}
</style>
</head>
<body>
<main>
  <h1>Speeches</h1>
  <ul>
{items}
  </ul>
</main>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pages", nargs="+", help="slug=title=path/to/page.html")
    args = ap.parse_args()
    secret = passphrase()
    entries = []
    for spec in args.pages:
        slug, title, path = spec.split("=", 2)
        payload = encrypt(Path(path).read_bytes(), secret)
        out = SITE / slug / "index.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(build_page(title, payload))
        entries.append((slug, title))
        print(f"Locked {path} -> {out.relative_to(ROOT)}")
    (SITE / "index.html").write_text(build_index(entries))
    (SITE / "robots.txt").write_text("User-agent: *\nDisallow: /\n")
    (SITE / ".nojekyll").write_text("")


if __name__ == "__main__":
    main()
