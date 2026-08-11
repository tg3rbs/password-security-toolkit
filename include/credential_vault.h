#ifndef CREDENTIAL_VAULT_H
#define CREDENTIAL_VAULT_H

#include "credential.h"

#include <string>
#include <vector>

class CredentialVault {
public:
    CredentialVault(
    const std::string& vaultFilePath,
    const std::vector<unsigned char>& encryptionKey
    );

    void addCredential(
        const Credential& credential
    );

    void displayCredentials() const;

    bool saveVault() const;
    bool loadVault();

private:
    std::string vaultFilePath;
    
    std::vector<unsigned char> encryptionKey;

    std::vector<Credential> credentials;
};

#endif