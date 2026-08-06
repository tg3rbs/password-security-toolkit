#include "file_integrity.h"
#include "sha256.h"

#include <fstream>
#include <sstream>
#include <string>

using namespace std;

namespace {

bool readEntireFile(
    const string& filename,
    string& contents
) {
    ifstream inputFile(filename, ios::binary);

    if (!inputFile.is_open()) {
        return false;
    }

    stringstream buffer;
    buffer << inputFile.rdbuf();

    contents = buffer.str();

    return true;
}

}  // namespace

bool updateFileHash(
    const string& filename,
    const string& hashFilePath
) {
    string fileContents;

    if (!readEntireFile(filename, fileContents)) {
        return false;
    }

    const string currentHash = sha256(fileContents);

    ofstream hashFile(hashFilePath);

    if (!hashFile.is_open()) {
        return false;
    }

    hashFile << currentHash << '\n';

    return true;
}

bool verifyFileIntegrity(
    const string& filename,
    const string& hashFilePath
) {
    string fileContents;

    if (!readEntireFile(filename, fileContents)) {
        return false;
    }

    ifstream hashFile(hashFilePath);

    if (!hashFile.is_open()) {
        return false;
    }

    string storedHash;
    getline(hashFile, storedHash);

    const string currentHash = sha256(fileContents);

    return currentHash == storedHash;
}