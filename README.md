# Password Security Toolkit

A C++17 command-line password manager implementing account authentication, encrypted credential storage, password generation, integrity verification, and per-user credential vaults.

The project explores the design and implementation of a password-management system using established cryptographic primitives provided by OpenSSL.

## Features

### Account Management

- Account creation and authentication
- Password strength validation
- Salted password hashing
- Duplicate username prevention
- Failed-login tracking and temporary account lockout
- Password changes and account deletion

### Encrypted Credential Vaults

Each account has an independent vault for storing service names, usernames or email addresses, and passwords.

Supported operations include:

- Add, view, edit, and delete credentials
- Duplicate credential prevention
- Persistent encrypted storage
- Automatic vault re-encryption after a master-password change

Credential passwords are encrypted before being written to disk.

### Cryptography

Vault passwords are protected with **AES-256-GCM** using OpenSSL. GCM provides authenticated encryption, allowing the application to detect modification of encrypted credential data during decryption.

Encryption keys are derived from the user's master password using **PBKDF2** and a persistent per-user salt:

```text
Master Password
      +
 Vault Salt
      |
      v
    PBKDF2
      |
      v
256-bit AES Key
      |
      v
 AES-256-GCM
```

Each encrypted password is stored with the nonce and authentication tag required for authenticated decryption.

When a master password changes, the existing vault is decrypted using the previous derived key and re-encrypted using a key derived from the new password.

### Password Generation

The toolkit can generate passwords using cryptographically secure random data provided by OpenSSL. Users may either supply a credential password manually or generate one through the application.

### Integrity Verification

A SHA-256 digest is maintained for account data. At startup, the application compares the current account file against the previously stored digest and warns when unexpected modification is detected.

## Architecture

Authentication and credential encryption are handled separately.

```text
                    Password Security Toolkit
                              |
              +---------------+---------------+
              |                               |
        Authentication                  Credential Vault
              |                               |
       Salted Hashing                   Master Password
              |                               |
         users.txt                      PBKDF2 + Salt
                                              |
                                              v
                                         256-bit Key
                                              |
                                              v
                                        AES-256-GCM
                                              |
                                              v
                                      Encrypted Vault
```

Authentication verifies account credentials, while separately derived cryptographic keys protect vault contents.

## Project Structure

```text
password-security-toolkit/
├── include/
│   ├── credential.h
│   ├── credential_vault.h
│   ├── file_integrity.h
│   ├── password_generator.h
│   ├── password_manager.h
│   ├── sha256.h
│   └── vault_crypto.h
├── src/
│   ├── credential_vault.cpp
│   ├── file_integrity.cpp
│   ├── main.cpp
│   ├── password_generator.cpp
│   ├── password_manager.cpp
│   ├── sha256.cpp
│   └── vault_crypto.cpp
├── tests/
├── data/
├── LICENSE
└── README.md
```

## Requirements

- C++17-compatible compiler
- OpenSSL 3
- macOS, Linux, or another environment with the required OpenSSL headers and libraries configured

### macOS

Install OpenSSL with Homebrew:

```bash
brew install openssl@3
```

Locate the installation:

```bash
brew --prefix openssl@3
```

On Apple Silicon, the default path is typically:

```text
/opt/homebrew/opt/openssl@3
```

## Build

From the project root:

```bash
g++ -std=c++17 \
    -Wall \
    -Wextra \
    -Wpedantic \
    src/main.cpp \
    src/password_manager.cpp \
    src/sha256.cpp \
    src/file_integrity.cpp \
    src/credential_vault.cpp \
    src/vault_crypto.cpp \
    src/password_generator.cpp \
    -Iinclude \
    -I/opt/homebrew/opt/openssl@3/include \
    -L/opt/homebrew/opt/openssl@3/lib \
    -lssl \
    -lcrypto \
    -o password_toolkit
```

## Usage

Run the compiled executable:

```bash
./password_toolkit
```

The application begins with account creation and authentication. After authentication, the user can manage credentials in the vault associated with that account.

## Data Storage

Runtime data is stored under `data/`.

The application maintains:

- Account records
- Account-file integrity data
- Per-user encrypted vaults
- Per-user vault salts

Vault filenames use derived user identifiers rather than plaintext usernames.

## Testing

The application has been manually tested for account creation, authentication failures, lockout behavior, password validation, credential CRUD operations, password generation, persistence across restarts, encrypted storage, vault tamper detection, master-password changes, vault re-encryption, account deletion, and account-file integrity verification.

The project compiles without warnings using:

```text
-Wall -Wextra -Wpedantic
```

## Security Considerations

This project is an educational implementation and has not undergone a professional security audit. It should not be used as a replacement for a production password manager.

A production system would require additional controls such as hardened secret handling in memory, platform-backed key storage, comprehensive automated and adversarial testing, secure backup and recovery mechanisms, and independent security review.

## License

See `LICENSE` for licensing information.
