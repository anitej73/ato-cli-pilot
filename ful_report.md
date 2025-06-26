# ATO Compliance Scan Results

## SC-12
❌ **NOT COMPLIANT** – No HTTPS or TLS detected

🛠️ Suggestion: Use TLS 1.2+ or secure endpoints

**Failing files:**
- `ato_cli\oscal_writer.py` – No HTTPS or TLS detected
- `ato_cli\__init__.py` – No HTTPS or TLS detected

## AC-2
❌ **NOT COMPLIANT** – No account-management found

🛠️ Suggestion: Implement user provisioning (e.g., create_user)

**Failing files:**
- `ato_cli\oscal_writer.py` – No account-management found
- `ato_cli\__init__.py` – No account-management found

## SC-13
❌ **NOT COMPLIANT** – No encryption-at-rest code found

🛠️ Suggestion: Use AES-256, a managed KMS key, or a cloud key-vault service to encrypt data at rest

**Failing files:**
- `ato_cli\oscal_writer.py` – No encryption-at-rest code found
- `ato_cli\__init__.py` – No encryption-at-rest code found

## CM-2
❌ **NOT COMPLIANT** – No baseline configuration file detected

🛠️ Suggestion: Add or document a secured baseline configuration (e.g., .conf / .ini file)

**Failing files:**
- `ato_cli\cli.py` – No baseline configuration file detected
- `ato_cli\oscal_writer.py` – No baseline configuration file detected
- `ato_cli\__init__.py` – No baseline configuration file detected

