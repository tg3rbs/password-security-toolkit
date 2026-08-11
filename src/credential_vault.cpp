#include "credential_vault.h"
#include "vault_crypto.h"

#include <iostream>
#include <fstream>
#include <stdexcept>

using namespace std;

CredentialVault::CredentialVault(
    const string& vaultFilePath,
    const vector<unsigned char>& encryptionKey
)
    : vaultFilePath(vaultFilePath),
      encryptionKey(encryptionKey) {

    if (encryptionKey.size() != 32) {
        throw runtime_error(
            "Credential vault requires a 32-byte encryption key."
        );
    }
}

bool CredentialVault::saveVault() const {
    ofstream outputFile(vaultFilePath);

    if (!outputFile.is_open()) {
        return false;
    }

    for (const Credential& credential : credentials) {
        outputFile
            << credential.service << ":"
            << credential.username << '\n';
    }

    return true;
}

bool CredentialVault::loadVault() {
    ifstream inputFile(vaultFilePath);

    if (!inputFile.is_open()) {
        return false;
    }

    credentials.clear();

    string service;
    string username;

    while (
        getline(inputFile, service, ':') &&
        getline(inputFile, username)
    ) {
        Credential credential;

        credential.service = service;
        credential.username = username;
        credential.password = "";

        credentials.push_back(credential);
    }

    return true;
}

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