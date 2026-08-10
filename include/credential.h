#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <string>

struct Credential {
    std::string service;
    std::string username;
    std::string password;
};

#endif