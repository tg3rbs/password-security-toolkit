#ifndef VAULT_CRYPTO_H
#define VAULT_CRYPTO_H

#include <string>
#include <vector>

struct EncryptedData {
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
};

EncryptedData encryptPassword(
    const std::string& plaintext,
    const std::vector<unsigned char>& key
);

std::string decryptPassword(
    const EncryptedData& encryptedData,
    const std::vector<unsigned char>& key
);

std::vector<unsigned char> generateKeySalt();

std::vector<unsigned char> deriveKey(
    const std::string& password,
    const std::vector<unsigned char>& salt
);

bool saveKeySalt(
    const std::string& filePath,
    const std::vector<unsigned char>& salt
);

bool loadKeySalt(
    const std::string& filePath,
    std::vector<unsigned char>& salt
);

#endif