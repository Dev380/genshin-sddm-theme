import hashlib
import base64
import sys
import secrets

username = sys.argv[1]
password = sys.argv[2]
salt = secrets.token_bytes(16)

hash = hashlib.pbkdf2_hmac("sha256", bytes(password, "utf-8"), salt, 10_000, dklen=32)
print(f"{username}:{(base64.b64encode(salt)).decode('utf-8')}:{base64.b64encode(hash).decode('utf-8')}")
