#ifndef SHA256_H
#define SHA256_H

#include <string>

// Returns the 64-character hexadecimal SHA-256 digest of the input.
std::string sha256(const std::string& input);

#endif