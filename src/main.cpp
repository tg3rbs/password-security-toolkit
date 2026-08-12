#include "password_manager.h"
#include "file_integrity.h"
#include "credential.h"
#include "credential_vault.h"
#include "vault_crypto.h"
#include "sha256.h"

#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

using namespace std;

void displayMenu() {
    cout << "\nPassword Security Toolkit\n";
    cout << "-------------------------\n";
    cout << "1. Create account\n";
    cout << "2. Log in\n";
    cout << "3. View cache statistics\n";
    cout << "4. Clear cache\n";
    cout << "5. Change password\n";
    cout << "6. Delete account\n";
    cout << "7. Exit\n";
    cout << "Enter your choice: ";
}

void createAccountMenu(PasswordManager& passwordManager) {
    string username;
    string password;

    cout << "\nCreate Account\n";
    cout << "Username: ";
    getline(cin, username);

    cout << "Password: ";
    getline(cin, password);

    const bool accountCreated =
        passwordManager.createAccount(username, password);

    if (accountCreated) {
        cout << "Account created successfully.\n";
    }
    else {
        cout << "Account could not be created.\n";
        cout << "The username may already exist, "
             << "or the input may be invalid.\n";
    }
}

void vaultMenu(CredentialVault& vault) {
    int choice = 0;

    while (choice != 5) {
        cout << "\nCredential Vault\n";
        cout << "----------------\n";
        cout << "1. Add credential\n";
        cout << "2. View credentials\n";
        cout << "3. Delete credential\n";
        cout << "4. Edit credential\n";
        cout << "5. Logout\n";
        cout << "Enter your choice: ";

        if (!(cin >> choice)) {
            cout << "Invalid input.\n";

            cin.clear();
            cin.ignore(
                numeric_limits<streamsize>::max(),
                '\n'
            );

            continue;
        }

        cin.ignore(
            numeric_limits<streamsize>::max(),
            '\n'
        );

        switch (choice) {
            case 1: {
                Credential credential;

                cout << "Service: ";
                getline(cin, credential.service);

                cout << "Username/email: ";
                getline(cin, credential.username);

                cout << "Password: ";
                getline(cin, credential.password);

                vault.addCredential(credential);

                if (vault.saveVault()) {
                    cout << "Credential saved.\n";
                }
                else {
                    cout << "Credential could not be saved.\n";
                }

                break;
            }

            case 2:
                vault.displayCredentials();
                break;

            case 3: {
                string service;
                string username;

                cout << "Service: ";
                getline(cin, service);

                cout << "Username/email: ";
                getline(cin, username);

                if (vault.deleteCredential(service, username)) {
                    cout << "Credential deleted successfully.\n";
                }
                else {
                    cout << "Credential not found.\n";
                }

                break;
            }

            case 4: {
                string service;
                string username;

                cout << "Current service: ";
                getline(cin, service);

                cout << "Current username/email: ";
                getline(cin, username);

                Credential updatedCredential;

                cout << "New service: ";
                getline(cin, updatedCredential.service);

                cout << "New username/email: ";
                getline(cin, updatedCredential.username);

                cout << "New password: ";
                getline(cin, updatedCredential.password);

                if (
                    vault.editCredential(
                        service,
                        username,
                        updatedCredential
                    )
                ) {
                    cout << "Credential updated successfully.\n";
                }
                else {
                    cout << "Credential not found.\n";
                }

                break;
            }

            case 5:
                cout << "Logged out.\n";
                break;

            default:
                cout << "Enter a number from 1 to 5.\n";
        }
    }
}

void loginMenu(const PasswordManager& passwordManager) {
    string username;
    string password;

    cout << "\nLog In\n";
    cout << "Username: ";
    getline(cin, username);

    cout << "Password: ";
    getline(cin, password);

    if (passwordManager.isAccountLocked(username)) {
    cout << "Account is locked due to too many failed login attempts.\n";
    return;
    }

    const bool loginSuccessful =
        passwordManager.verifyLogin(username, password);

    if (loginSuccessful) {
        cout << "Login successful.\n";

        const string userIdentifier =
            sha256(username).substr(0, 16);

        const string vaultFilePath =
            "data/vault_" + userIdentifier + ".txt";

        const string vaultSaltPath =
            "data/vault_" + userIdentifier + ".salt";

        vector<unsigned char> vaultSalt;

        if (filesystem::exists(vaultSaltPath)) {
            if (!loadKeySalt(vaultSaltPath, vaultSalt)) {
                cout << "Could not load vault salt.\n";
                return;
            }
        }
        else {
            vaultSalt = generateKeySalt();

            if (!saveKeySalt(vaultSaltPath, vaultSalt)) {
                cout << "Could not save vault salt.\n";
                return;
            }
        }

        vector<unsigned char> vaultKey =
            deriveKey(password, vaultSalt);

        CredentialVault vault(
            vaultFilePath,
            vaultKey
        );

        if (filesystem::exists(vaultFilePath)) {
            if (!vault.loadVault()) {
                cout << "Could not decrypt or load vault.\n";
                return;
            }
        }

        vaultMenu(vault);
    }
    else {
        cout << "Invalid username or password.\n";
    }
}

void changePasswordMenu(PasswordManager& passwordManager) {
    string username;
    string currentPassword;
    string newPassword;

    cout << "\nChange Password\n";

    cout << "Username: ";
    getline(cin, username);

    cout << "Current password: ";
    getline(cin, currentPassword);

    cout << "New password: ";
    getline(cin, newPassword);

    const bool passwordChanged =
        passwordManager.changePassword(
            username,
            currentPassword,
            newPassword
        );

    if (passwordChanged) {
        cout << "Password changed successfully.\n";
    }
    else {
        cout << "Password could not be changed.\n";
    }
}

void deleteAccountMenu(PasswordManager& passwordManager) {
    string username;
    string password;

    cout << "\nDelete Account\n";

    cout << "Username: ";
    getline(cin, username);

    cout << "Password: ";
    getline(cin, password);

    const bool accountDeleted =
        passwordManager.deleteAccount(
            username,
            password
        );

    if (accountDeleted) {
        cout << "Account deleted successfully.\n";
    }
    else {
        cout << "Account could not be deleted.\n";
    }
}

int main() {
    filesystem::create_directories("data");

    const string userFilePath = "data/users.txt";
    const string integrityFilePath = "data/users.sha256";

    PasswordManager passwordManager(
    userFilePath,
    integrityFilePath
    );

    if (filesystem::exists(integrityFilePath)) {
        if (verifyFileIntegrity(userFilePath, integrityFilePath)) {
            cout << "File integrity verified.\n";
        }
        else {
            cout << "WARNING: users.txt may have been modified.\n";
        }
    }
    else {
        if (updateFileHash(userFilePath, integrityFilePath)) {
            cout << "Integrity hash created.\n";
        }
        else {
            cout << "Could not create integrity hash.\n";
        }
    }

    int choice = 0;

    while (choice != 7) {
        displayMenu();

        if (!(cin >> choice)) {
            cout << "Invalid input. Enter a number from 1 to 7.\n";

            cin.clear();

            cin.ignore(
                numeric_limits<streamsize>::max(),
                '\n'
            );

            continue;
        }

        cin.ignore(
            numeric_limits<streamsize>::max(),
            '\n'
        );

        switch (choice) {
            case 1:
                createAccountMenu(passwordManager);
                break;

            case 2:
                loginMenu(passwordManager);
                break;

            case 3:
                passwordManager.displayCacheStats();
                break;

            case 4:
                passwordManager.clearCache();
                break;

            case 5:
                changePasswordMenu(passwordManager);
                break;

            case 6:
                deleteAccountMenu(passwordManager);
                break;

            case 7:
                cout << "Exiting program.\n";
                break;

            default:
                cout << "Enter a number from 1 to 7.\n";
        }
    }

    return 0;
}