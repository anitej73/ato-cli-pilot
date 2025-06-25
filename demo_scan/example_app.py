import requests
from Crypto.Cipher import AES
def create_user(name, email):
    return {"name": name, "email": email}

def fetch_data():
    resp = requests.get("https://api.example.com/data", timeout=5)
    return resp.json()

key = b"0" * 32
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(b"secret".ljust(32, b"\0"))
