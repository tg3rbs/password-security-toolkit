#ifndef FILE_INTEGRITY_H
#define FILE_INTEGRITY_H

#include <string>

// Computes the current hash of filename and stores it in hashFilePath.
bool updateFileHash(
    const std::string& filename,
    const std::string& hashFilePath
);

// Compares the file's current hash with the stored hash.
bool verifyFileIntegrity(
    const std::string& filename,
    const std::string& hashFilePath
);

#endif