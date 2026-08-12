#include "password_manager.h"
#include "sha256.h"
#include "file_integrity.h"

#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <cctype>
#include <algorithm>
#include <cstdio>

using namespace std;

string trim(const string& str) {
    size_t start = str.find_first_not_of(" \t");
    if (start == string::npos) {
        return "";
    }

    size_t end = str.find_last_not_of(" \t");
    return str.substr(start, end - start + 1);
}

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
AccountCreationResult PasswordManager::createAccount(
    string username,
    const string& password
) {

    username = trim(username);

    if (username.empty()) {
        return AccountCreationResult::EmptyUsername;
    }

    if (password.empty()) {
        return AccountCreationResult::EmptyPassword;
    }

    if (!isStrongPassword(password)) {
        return AccountCreationResult::WeakPassword;
    }

    if (usernameExists(username)) {
        return AccountCreationResult::UsernameExists;
    }

    const string salt = generateSalt();
    const string passwordHash = hashPassword(password, salt);

    ofstream outputFile(userFilePath, ios::app);

    if (!outputFile.is_open()) {
        return AccountCreationResult::FileError;
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

    return AccountCreationResult::Success;
}

bool PasswordManager::verifyLogin(
    const string& username,
    const string& password
) const {
    const string cleanUsername = trim(username);

    if (isAccountLocked(cleanUsername)) {
    return false;
    }

    CachedAccount account;

    const auto cachedAccount =
        accountCache.find(cleanUsername);

    if (cachedAccount != accountCache.end()) {
        ++cacheHits;
        account = cachedAccount->second;
    }
    else {
        ++cacheMisses;

        if (!loadAccountFromFile(cleanUsername, account)) {
            return false;
        }

        accountCache[cleanUsername] = account;
    }

    const string attemptedHash =
        hashPassword(password, account.salt);

    if (attemptedHash == account.passwordHash) {
        failedAttempts[cleanUsername] = 0;
        return true;
    }

    ++failedAttempts[cleanUsername];

    if (failedAttempts[cleanUsername] >= 3) {
        lockedAccounts[cleanUsername] = true;
    }

    return false;
}

bool PasswordManager::changePassword(
    const string& username,
    const string& currentPassword,
    const string& newPassword
) {
    const string cleanUsername = trim(username);

    // The user must prove they know the current password.
    if (!verifyLogin(cleanUsername, currentPassword)) {
        return false;
    }

    // The new password must satisfy our password rules.
    if (!isStrongPassword(newPassword)) {
        return false;
    }

    const string newSalt = generateSalt();
    const string newHash = hashPassword(newPassword, newSalt);

    ifstream inputFile(userFilePath);

    if (!inputFile.is_open()) {
        return false;
    }

    const string temporaryFilePath = userFilePath + ".tmp";
    ofstream outputFile(temporaryFilePath);

    if (!outputFile.is_open()) {
        return false;
    }

    string storedUsername;
    string storedSalt;
    string storedHash;

    bool accountUpdated = false;

    while (
        getline(inputFile, storedUsername, ':') &&
        getline(inputFile, storedSalt, ':') &&
        getline(inputFile, storedHash)
    ) {
        if (storedUsername == cleanUsername) {
            outputFile
                << cleanUsername << ":"
                << newSalt << ":"
                << newHash << '\n';

            accountUpdated = true;
        }
        else {
            outputFile
                << storedUsername << ":"
                << storedSalt << ":"
                << storedHash << '\n';
        }
    }

    inputFile.close();
    outputFile.close();

    if (!accountUpdated) {
        remove(temporaryFilePath.c_str());
        return false;
    }

    if (remove(userFilePath.c_str()) != 0) {
        remove(temporaryFilePath.c_str());
        return false;
    }

    if (rename(
        temporaryFilePath.c_str(),
        userFilePath.c_str()
    ) != 0) {
        return false;
    }

    accountCache[cleanUsername] = {
        newSalt,
        newHash
    };

    if (!updateFileHash(
        userFilePath,
        integrityFilePath
    )) {
        return false;
    }

    return true;
}

bool PasswordManager::deleteAccount(
    const string& username,
    const string& password
) {
    const string cleanUsername = trim(username);

    // Require authentication before deleting the account.
    if (!verifyLogin(cleanUsername, password)) {
        return false;
    }

    ifstream inputFile(userFilePath);

    if (!inputFile.is_open()) {
        return false;
    }

    const string temporaryFilePath = userFilePath + ".tmp";
    ofstream outputFile(temporaryFilePath);

    if (!outputFile.is_open()) {
        return false;
    }

    string storedUsername;
    string storedSalt;
    string storedHash;

    bool accountDeleted = false;

    while (
        getline(inputFile, storedUsername, ':') &&
        getline(inputFile, storedSalt, ':') &&
        getline(inputFile, storedHash)
    ) {
        if (storedUsername == cleanUsername) {
            accountDeleted = true;
            continue;
        }

        outputFile
            << storedUsername << ":"
            << storedSalt << ":"
            << storedHash << '\n';
    }

    inputFile.close();
    outputFile.close();

    if (!accountDeleted) {
        remove(temporaryFilePath.c_str());
        return false;
    }

    if (remove(userFilePath.c_str()) != 0) {
        remove(temporaryFilePath.c_str());
        return false;
    }

    if (rename(
        temporaryFilePath.c_str(),
        userFilePath.c_str()
    ) != 0) {
        return false;
    }

    accountCache.erase(cleanUsername);

    if (!updateFileHash(
        userFilePath,
        integrityFilePath
    )) {
        return false;
    }

    return true;
}

bool PasswordManager::isAccountLocked(
    const string& username
) const {
    const string cleanUsername = trim(username);

    const auto locked = lockedAccounts.find(cleanUsername);

    return locked != lockedAccounts.end() && locked->second;
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