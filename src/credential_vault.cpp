#include "credential_vault.h"
#include <iostream>

using namespace std;

void CredentialVault::addCredential(
    const Credential& credential
) {
    credentials.push_back(credential);
}

void CredentialVault::displayCredentials() const {
    for (const Credential& credential : credentials) {
        cout << "Service: " << credential.service << '\n';
        cout << "Username: " << credential.username << '\n';
        cout << "Password: " << credential.password << '\n';
        cout << '\n';
    }
}