# ATO Compliance Scan Results

## SC-12
✅ **COMPLIANT** – All scanned files passed.

## AC-2
✅ **COMPLIANT** – All scanned files passed.

## SC-13
❌ **NOT COMPLIANT** – No encryption-at-rest code found

🛠️ Suggestion: Use AES-256, a managed KMS key, or a cloud key-vault service to encrypt data at rest

**Failing files:**
- `good_app.py` – No encryption-at-rest code found

## CM-2
❌ **NOT COMPLIANT** – No baseline configuration file detected

🛠️ Suggestion: Add or document a secured baseline configuration (e.g., .conf / .ini file)

**Failing files:**
- `good_app.py` – No baseline configuration file detected
- `bad_storage.js` – No baseline configuration file detected

