#include "password_generator.h"

#include <openssl/rand.h>

#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

string generatePassword(
    size_t length
) {
    if (length < 8) {
        throw invalid_argument(
            "Password length must be at least 8."
        );
    }

    const string characters =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+";

    const unsigned int characterCount =
        static_cast<unsigned int>(characters.size());

    const unsigned int limit =
        256 - (256 % characterCount);

    string password;
    password.reserve(length);

    while (password.size() < length) {
        unsigned char randomByte;

        if (
            RAND_bytes(
                &randomByte,
                1
            ) != 1
        ) {
            throw runtime_error(
                "Failed to generate secure random bytes."
            );
        }

        if (randomByte >= limit) {
            continue;
        }

        password += characters[
            randomByte % characterCount
        ];
    }

    return password;
}