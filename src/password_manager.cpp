#include "password_manager.h"
#include "sha256.h"
#include "file_integrity.h"

#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <cctype>
#include <algorithm>

using namespace std;

PasswordManager::PasswordManager(
    const string& userFilePath,
    const string& integrityFilePath
)
    : userFilePath(userFilePath),
      integrityFilePath(integrityFilePath),
      cacheHits(0),
      cacheMisses(0) {
}

string PasswordManager::generateSalt() const {
    const string characters =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    random_device randomDevice;
    mt19937 generator(randomDevice());

    uniform_int_distribution<size_t> distribution(
        0,
        characters.size() - 1
    );

    string salt;

    const int SALT_LENGTH = 16;

    for (int i = 0; i < SALT_LENGTH; ++i) {
        salt += characters.at(distribution(generator));
    }

    return salt;
}

string PasswordManager::hashPassword(
    const string& password,
    const string& salt
) const {
    const string saltedPassword = salt + password;

    return sha256(saltedPassword);
}

bool PasswordManager::loadAccountFromFile(
    const string& username,
    CachedAccount& account
) const {
    ifstream inputFile(userFilePath);

    if (!inputFile.is_open()) {
        return false;
    }

    string storedUsername;
    string storedSalt;
    string storedHash;

    while (
        getline(inputFile, storedUsername, ':') &&
        getline(inputFile, storedSalt, ':') &&
        getline(inputFile, storedHash)
    ) {
        if (storedUsername == username) {
            account.salt = storedSalt;
            account.passwordHash = storedHash;

            return true;
        }
    }

    return false;
}

bool PasswordManager::usernameExists(const string& username) const {
    if (accountCache.find(username) != accountCache.end()) {
        return true;
    }

    CachedAccount account;

    return loadAccountFromFile(username, account);
}
bool PasswordManager::isStrongPassword(
    const string& password
) const {

    if (password.length() < 8) {
        return false;
    }

    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;

    for (char c : password) {

        if (isupper(c))
            hasUpper = true;

        else if (islower(c))
            hasLower = true;

        else if (isdigit(c))
            hasDigit = true;
    }

    return hasUpper && hasLower && hasDigit;
}
bool PasswordManager::createAccount(
    const string& username,
    const string& password
) {
    if (username.empty() || password.empty()) {
        return false;
    }

    if (usernameExists(username)) {
        return false;
    }
    if (!isStrongPassword(password)) {
        return false;
    }

    const string salt = generateSalt();
    const string passwordHash = hashPassword(password, salt);

    ofstream outputFile(userFilePath, ios::app);

    if (!outputFile.is_open()) {
        return false;
    }

    outputFile
        << username << ":"
        << salt << ":"
        << passwordHash << '\n';

    outputFile.close();

    CachedAccount account;

    account.salt = salt;
    account.passwordHash = passwordHash;

    accountCache[username] = account;

    updateFileHash(
    userFilePath,
    integrityFilePath
    );

    return true;
}

bool PasswordManager::verifyLogin(
    const string& username,
    const string& password
) const {
    CachedAccount account;

    const auto cachedAccount = accountCache.find(username);

    if (cachedAccount != accountCache.end()) {
        ++cacheHits;

        account = cachedAccount->second;
    }
    else {
        ++cacheMisses;

        if (!loadAccountFromFile(username, account)) {
            return false;
        }

        accountCache[username] = account;
    }

    const string attemptedHash =
        hashPassword(password, account.salt);

    return attemptedHash == account.passwordHash;
}

void PasswordManager::displayCacheStats() const {
    cout << "\nCache Statistics\n";
    cout << "----------------\n";
    cout << "Cached accounts: " << accountCache.size() << '\n';
    cout << "Cache hits: " << cacheHits << '\n';
    cout << "Cache misses: " << cacheMisses << '\n';
}

void PasswordManager::clearCache() {
    accountCache.clear();

    cacheHits = 0;
    cacheMisses = 0;
}