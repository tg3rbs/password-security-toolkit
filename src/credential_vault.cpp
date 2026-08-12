#include "credential_vault.h"
#include "vault_crypto.h"

#include <iostream>
#include <fstream>
#include <stdexcept>

using namespace std;

string bytesToHex(
    const vector<unsigned char>& bytes
) {
    const char hexCharacters[] = "0123456789abcdef";

    string result;
    result.reserve(bytes.size() * 2);

    for (unsigned char byte : bytes) {
        result += hexCharacters[(byte >> 4) & 0x0F];
        result += hexCharacters[byte & 0x0F];
    }

    return result;
}

vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;

    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);

        unsigned char byte =
            static_cast<unsigned char>(
                stoi(byteString, nullptr, 16)
            );

        bytes.push_back(byte);
    }

    return bytes;
}

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
        EncryptedData encryptedPassword =
            encryptPassword(
                credential.password,
                encryptionKey
            );

        outputFile
            << credential.service << ":"
            << credential.username << ":"
            << bytesToHex(encryptedPassword.nonce) << ":"
            << bytesToHex(encryptedPassword.ciphertext) << ":"
            << bytesToHex(encryptedPassword.tag) << '\n';
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
    string nonceHex;
    string ciphertextHex;
    string tagHex;

    while (
        getline(inputFile, service, ':') &&
        getline(inputFile, username, ':') &&
        getline(inputFile, nonceHex, ':') &&
        getline(inputFile, ciphertextHex, ':') &&
        getline(inputFile, tagHex)
    ) {
        EncryptedData encryptedPassword;

        encryptedPassword.nonce =
            hexToBytes(nonceHex);

        encryptedPassword.ciphertext =
            hexToBytes(ciphertextHex);

        encryptedPassword.tag =
            hexToBytes(tagHex);

        Credential credential;

        credential.service = service;
        credential.username = username;

        try {
            credential.password =
                decryptPassword(
                    encryptedPassword,
                    encryptionKey
                );
        }
        catch (const exception&) {
            return false;
        }

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

bool CredentialVault::deleteCredential(
    const string& service,
    const string& username
) {
    for (auto it = credentials.begin();
         it != credentials.end();
         ++it) {

        if (
            it->service == service &&
            it->username == username
        ) {
            credentials.erase(it);

            return saveVault();
        }
    }

    return false;
}

bool CredentialVault::editCredential(
    const string& service,
    const string& username,
    const Credential& updatedCredential
) {
    for (Credential& credential : credentials) {
        if (
            credential.service == service &&
            credential.username == username
        ) {
            credential = updatedCredential;

            return saveVault();
        }
    }

    return false;
}