#!/usr/bin/env python3
"""Encrypt crm_data.json -> data.enc.json for the static CRM.
Usage: python3 encrypt.py <plaintext.json> <out.enc.json> <email> <password>
Key = PBKDF2-HMAC-SHA256(email.lower()+":"+password, salt, 200k) ; AES-256-GCM.
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

src, out, email, password = sys.argv[1:5]
data = open(src, "rb").read()
salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
key = kdf.derive((email.strip().lower() + ":" + password).encode())
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, data, None)
json.dump({"v": 1, "kdf": "PBKDF2-SHA256-200000",
           "salt": base64.b64encode(salt).decode(),
           "nonce": base64.b64encode(nonce).decode(),
           "ct": base64.b64encode(ct).decode()}, open(out, "w"))
print(f"encrypted {len(data)} bytes -> {out}")
