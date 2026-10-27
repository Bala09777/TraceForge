#!/usr/bin/env python3
import json
import os
import secrets
from pathlib import Path
from getpass import getpass
from werkzeug.security import generate_password_hash

BASE = Path(__file__).resolve().parent
INSTANCE = BASE / "instance"
CONFIG = INSTANCE / "config.json"

INSTANCE.mkdir(mode=0o700, parents=True, exist_ok=True)

if CONFIG.exists():
    print("Config already exists; refusing to overwrite it.")
    raise SystemExit(1)

password = getpass("Create admin password (minimum 14 characters): ")
confirm = getpass("Confirm password: ")

if len(password) < 14:
    print("Password must contain at least 14 characters.")
    raise SystemExit(1)
if password != confirm:
    print("Passwords do not match.")
    raise SystemExit(1)

data = {
    "secret_key": secrets.token_urlsafe(48),
    "password_hash": generate_password_hash(password),
}

fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(data, f)
    f.write("\n")

os.chmod(INSTANCE, 0o700)
print("Private admin configuration created successfully.")
print("Keep webapp/instance/config.json private; never upload it to GitHub.")
