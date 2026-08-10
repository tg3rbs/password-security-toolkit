#include "password_manager.h"
#include "file_integrity.h"
#include "credential.h"
#include "credential_vault.h"

#include <filesystem>
#include <iostream>
#include <limits>
#include <string>

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