#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <cstddef>
#include <string>
#include <unordered_map>

class PasswordManager {
public:
    PasswordManager(
    const std::string& userFilePath,
    const std::string& integrityFilePath
    );

    bool createAccount(
        std::string username,
        const std::string& password
    );

    bool verifyLogin(
        const std::string& username,
        const std::string& password
    ) const;

    void displayCacheStats() const;

    void clearCache();

private:
    struct CachedAccount {
        std::string salt;
        std::string passwordHash;
    };

    std::string userFilePath;
    std::string integrityFilePath;

    mutable std::unordered_map<std::string, CachedAccount> accountCache;

    mutable std::size_t cacheHits;
    mutable std::size_t cacheMisses;

    std::string generateSalt() const;

    std::string hashPassword(
        const std::string& password,
        const std::string& salt
    ) const;

    bool loadAccountFromFile(
        const std::string& username,
        CachedAccount& account
    ) const;

    bool usernameExists(const std::string& username) const;

    bool isStrongPassword(
    const std::string& password
    ) const;
};

#endif