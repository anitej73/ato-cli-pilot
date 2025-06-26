# This file is designed to trigger 2 compliant and 2 non-compliant controls.

import requests

# SC-12: Encryption in transit (compliant)
response = requests.get("https://example.com/api/data")

# SC-13: Encryption at rest (compliant)
from Crypto.Cipher import AES
cipher = AES.new(b'Sixteen byte key', AES.MODE_EAX)

# AC-2: Account management (not compliant)
# (No user creation logic present)

# CM-2: Baseline configuration (not compliant)
# (No .conf/.ini/.cfg file and no 'baseline' in filename)
