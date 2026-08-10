#ifndef CREDENTIAL_VAULT_H
#define CREDENTIAL_VAULT_H

#include "credential.h"

#include <string>
#include <vector>

class CredentialVault {
public:
    void addCredential(
        const Credential& credential
    );

    void displayCredentials() const;

private:
    std::vector<Credential> credentials;
};

#endif