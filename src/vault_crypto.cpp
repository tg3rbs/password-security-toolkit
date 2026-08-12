#include "vault_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdexcept>
#include <fstream>

using namespace std;

vector<unsigned char> generateKeySalt() {
    vector<unsigned char> salt(16);

    if (
        RAND_bytes(
            salt.data(),
            static_cast<int>(salt.size())
        ) != 1
    ) {
        throw runtime_error(
            "Failed to generate key-derivation salt."
        );
    }

    return salt;
}

vector<unsigned char> deriveKey(
    const string& password,
    const vector<unsigned char>& salt
) {
    const int KEY_LENGTH = 32;
    const int ITERATIONS = 200000;

    vector<unsigned char> key(KEY_LENGTH);

    const int result =
        PKCS5_PBKDF2_HMAC(
            password.c_str(),
            static_cast<int>(password.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            ITERATIONS,
            EVP_sha256(),
            KEY_LENGTH,
            key.data()
        );

    if (result != 1) {
        throw runtime_error(
            "Failed to derive encryption key."
        );
    }

    return key;
}

bool saveKeySalt(
    const string& filePath,
    const vector<unsigned char>& salt
) {
    ofstream outputFile(filePath, ios::binary);

    if (!outputFile.is_open()) {
        return false;
    }

    outputFile.write(
        reinterpret_cast<const char*>(salt.data()),
        static_cast<streamsize>(salt.size())
    );

    return outputFile.good();
}

bool loadKeySalt(
    const string& filePath,
    vector<unsigned char>& salt
) {
    ifstream inputFile(filePath, ios::binary);

    if (!inputFile.is_open()) {
        return false;
    }

    salt.resize(16);

    inputFile.read(
        reinterpret_cast<char*>(salt.data()),
        static_cast<streamsize>(salt.size())
    );

    return inputFile.gcount() ==
        static_cast<streamsize>(salt.size());
}

EncryptedData encryptPassword(
    const string& plaintext,
    const vector<unsigned char>& key
) {
    if (key.size() != 32) {
        throw runtime_error(
            "AES-256 requires a 32-byte key."
        );
    }

    EncryptedData encryptedData;

    // AES-GCM commonly uses a 12-byte nonce.
    encryptedData.nonce.resize(12);

    if (
        RAND_bytes(
            encryptedData.nonce.data(),
            encryptedData.nonce.size()
        ) != 1
    ) {
        throw runtime_error(
            "Failed to generate random nonce."
        );
    }

    EVP_CIPHER_CTX* context =
        EVP_CIPHER_CTX_new();

    if (context == nullptr) {
        throw runtime_error(
            "Failed to create encryption context."
        );
    }

    encryptedData.ciphertext.resize(
        plaintext.size()
    );

    encryptedData.tag.resize(16);

    int outputLength = 0;
    int finalLength = 0;

    if (
        EVP_EncryptInit_ex(
            context,
            EVP_aes_256_gcm(),
            nullptr,
            nullptr,
            nullptr
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to initialize AES-256-GCM."
        );
    }

    if (
        EVP_EncryptInit_ex(
            context,
            nullptr,
            nullptr,
            key.data(),
            encryptedData.nonce.data()
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to set encryption key and nonce."
        );
    }

    if (
        EVP_EncryptUpdate(
            context,
            encryptedData.ciphertext.data(),
            &outputLength,
            reinterpret_cast<const unsigned char*>(
                plaintext.data()
            ),
            plaintext.size()
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to encrypt password."
        );
    }

    if (
        EVP_EncryptFinal_ex(
            context,
            encryptedData.ciphertext.data()
                + outputLength,
            &finalLength
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to finalize encryption."
        );
    }

    encryptedData.ciphertext.resize(
        outputLength + finalLength
    );

    if (
        EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_GET_TAG,
            encryptedData.tag.size(),
            encryptedData.tag.data()
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to retrieve authentication tag."
        );
    }

    EVP_CIPHER_CTX_free(context);

    return encryptedData;
}

string decryptPassword(
    const EncryptedData& encryptedData,
    const vector<unsigned char>& key
) {
    if (key.size() != 32) {
        throw runtime_error(
            "AES-256 requires a 32-byte key."
        );
    }

    EVP_CIPHER_CTX* context =
        EVP_CIPHER_CTX_new();

    if (context == nullptr) {
        throw runtime_error(
            "Failed to create decryption context."
        );
    }

    vector<unsigned char> plaintext(
        encryptedData.ciphertext.size()
    );

    int outputLength = 0;
    int finalLength = 0;

    if (
        EVP_DecryptInit_ex(
            context,
            EVP_aes_256_gcm(),
            nullptr,
            nullptr,
            nullptr
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to initialize AES-256-GCM decryption."
        );
    }

    if (
        EVP_DecryptInit_ex(
            context,
            nullptr,
            nullptr,
            key.data(),
            encryptedData.nonce.data()
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to set decryption key and nonce."
        );
    }

    if (
        EVP_DecryptUpdate(
            context,
            plaintext.data(),
            &outputLength,
            encryptedData.ciphertext.data(),
            encryptedData.ciphertext.size()
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to decrypt ciphertext."
        );
    }

    if (
        EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_TAG,
            encryptedData.tag.size(),
            const_cast<unsigned char*>(
                encryptedData.tag.data()
            )
        ) != 1
    ) {
        EVP_CIPHER_CTX_free(context);

        throw runtime_error(
            "Failed to set authentication tag."
        );
    }

    const int finalResult =
        EVP_DecryptFinal_ex(
            context,
            plaintext.data() + outputLength,
            &finalLength
        );

    EVP_CIPHER_CTX_free(context);

    if (finalResult != 1) {
        throw runtime_error(
            "Decryption failed: invalid key or corrupted data."
        );
    }

    plaintext.resize(
        outputLength + finalLength
    );

    return string(
        plaintext.begin(),
        plaintext.end()
    );
}