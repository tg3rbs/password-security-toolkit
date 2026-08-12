# Password Security Toolkit

A C++17 command-line password security application featuring account authentication, encrypted credential storage, secure password generation, file integrity verification, and per-user credential vaults.

The project was built to explore practical applications of cryptography, authentication, secure storage, and defensive programming in C++.

## Features

### Account Security

- Create and manage user accounts
- Password strength validation
- Salted password hashing
- Duplicate username prevention
- Failed-login tracking and temporary account lockout
- Password changes
- Account deletion
- Account caching for faster repeated lookups

### Encrypted Credential Vault

Each user receives an independent credential vault capable of storing:

- Service names
- Usernames or email addresses
- Passwords

Vault functionality includes:

- Add credentials
- View credentials
- Edit credentials
- Delete credentials
- Duplicate credential prevention
- Persistent encrypted storage

Credential passwords are never intentionally stored in plaintext on disk.

### AES-256-GCM Encryption

Vault passwords are protected using AES-256-GCM through OpenSSL.

AES-GCM provides both:

- **Confidentiality** — stored passwords cannot be read without the encryption key
- **Authentication** — modification of encrypted data causes authentication to fail during decryption

Each encrypted password contains the data necessary for authenticated decryption, including a unique nonce and authentication tag.

### PBKDF2 Key Derivation

Vault encryption keys are derived from the user's master password using PBKDF2.

Rather than using the master password directly as an AES key:

```text
Master Password
      +
Per-User Vault Salt
      |
      v
    PBKDF2
      |
      v
256-bit Encryption Key
      |
      v
  AES-256-GCM
```

Each vault uses a persistent salt so the same master password can reproduce the correct encryption key during future logins.

When a master password is changed, the vault is decrypted with the old key and re-encrypted using a key derived from the new master password.

### Secure Password Generator

The toolkit can automatically generate strong passwords for stored credentials.

Generated passwords use cryptographically secure random data supplied by OpenSSL rather than standard pseudo-random number generation.

Users may either:

- Enter a password manually
- Generate a secure password automatically

### File Integrity Verification

The application maintains a SHA-256 integrity hash for account data.

At startup, the program verifies the account file against its previously stored hash and warns if the file may have been modified unexpectedly.

## Security Architecture

The application separates account authentication from credential encryption.

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

Account passwords are used for authentication while derived cryptographic keys protect credential vault contents.

## Project Structure

```text
password-security-toolkit/
|
|-- include/
|   |-- credential.h
|   |-- credential_vault.h
|   |-- file_integrity.h
|   |-- password_generator.h
|   |-- password_manager.h
|   |-- sha256.h
|   `-- vault_crypto.h
|
|-- src/
|   |-- credential_vault.cpp
|   |-- file_integrity.cpp
|   |-- main.cpp
|   |-- password_generator.cpp
|   |-- password_manager.cpp
|   |-- sha256.cpp
|   `-- vault_crypto.cpp
|
|-- tests/
|-- data/
|-- LICENSE
`-- README.md
```

## Technologies

- C++17
- OpenSSL
- AES-256-GCM
- PBKDF2
- SHA-256
- C++ Standard Library
- `std::filesystem`

## Requirements

The project requires:

- A C++17-compatible compiler
- OpenSSL 3
- macOS or another environment with the appropriate OpenSSL include/library paths configured

## Installing OpenSSL on macOS

Using Homebrew:

```bash
brew install openssl@3
```

To find the installed OpenSSL path:

```bash
brew --prefix openssl@3
```

On Apple Silicon Macs, Homebrew commonly installs OpenSSL under:

```text
/opt/homebrew/opt/openssl@3
```

## Building

From the project root:

```bash
g++ -std=c++17 \
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

For additional compiler diagnostics:

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

## Running

After compilation:

```bash
./password_toolkit
```

The main menu provides account-management functionality. After successful authentication, users can access their individual encrypted credential vault.

## Data Storage

Runtime data is stored inside the `data/` directory.

The application maintains files for:

- Account information
- Account-file integrity hashes
- Per-user encrypted vaults
- Per-user vault salts

Vault filenames use derived user identifiers rather than directly exposing usernames in filenames.

## Testing

The toolkit has been manually tested for:

- Valid and invalid account creation
- Password-strength enforcement
- Duplicate usernames
- Successful and failed authentication
- Login lockout behavior
- Manual credential creation
- Generated passwords
- Duplicate credential prevention
- Credential viewing
- Credential editing
- Credential deletion
- Vault persistence across program restarts
- Encrypted password storage
- Vault tamper detection
- Master-password changes
- Vault re-encryption after master-password changes
- Account deletion
- File-integrity verification

The project also compiles cleanly with:

```text
-Wall -Wextra -Wpedantic
```

## Security Notes

This project is intended as an educational implementation of password-management and cryptographic concepts.

Although it uses established cryptographic primitives through OpenSSL, it has not undergone a professional security audit and should not be treated as a replacement for a production password manager.

Real-world password managers require additional protections involving areas such as secure memory handling, hardened key management, platform-specific secret storage, extensive automated testing, secure backup/recovery systems, and independent security review.

## Concepts Demonstrated

This project demonstrates practical experience with:

- Object-oriented C++
- Modular header/source organization
- File I/O
- Authentication systems
- Password hashing and salting
- Cryptographic key derivation
- Authenticated encryption
- Cryptographically secure random generation
- File-integrity verification
- Persistent encrypted storage
- Input validation
- Error handling
- Account lockout logic
- Credential lifecycle management
- Security-oriented software design

## License

See `LICENSE` for licensing information.