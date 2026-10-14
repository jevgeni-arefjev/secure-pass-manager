# About this document

This document contains requirements for project as listed by course instructor. To preserve the exact contents, DO NOT CHANGE THIS DOCUMENT unless EXPLICITLY asked to. The resulting app must satisfy the requirements and deliverables listed below.

If requirements cause conflict, align with ICS0022 course requirements.

## ICS0022 Project: Secure Password Manager

This chapter presents the overview of the application to be built, its security requirements and the expected deliverables.

### 1. Overview

In this project you will develop a secure password manager application. The focus is on securely storing and managing user credentials, with an emphasis on encryption, secure memory handling, and protection against common vulnerabilities such as buffer overflows, improper input validation and unauthorised access.

### 2. Requirements

The application must satisfy the following security requirements.
- Secure storage of credentials. Implement strong encryption to store passwords and other sensitive information. Allow users to add, retrieve, update and delete stored credentials securely.
- Master password and authentication. Users access their vault using a master password, stored securely with a hashing method such as bcrypt, never in plaintext.
- Secure memory management. Sensitive data such as passwords must be wiped from memory immediately after use. Use secure allocation and deallocation practices to prevent leaks and data remnants.
- Input validation and sanitization. Validate all user inputs, such as usernames and passwords, to prevent injection attacks and ensure data integrity. Handle unexpected or malicious input safely.
- User interface and usability. A simple command-line or minimal graphical interface. The interface must be intuitive and must never display passwords in cleartext.
- Access control. Enforce per-user ownership on every record operation.
- Error handling and logging. Secure error handling that leaks no sensitive information, generic user-facing errors, and structured logging of key events such as login attempts and vault changes that never contains secrets.

### 3. Deliverables

The following deliverables are submitted at the end of the project.
- A secure password manager application with a user manual.
- A report detailing the encryption methods, memory management practices, and
security features implemented.
- A set of test cases and results demonstrating the application's security and
functionality.


## ICS0027 Project: Web-Based Secure Password Manager

This chapter presents the overview of the application to be built, its security requirements and the expected deliverables.

### 1. Overview

Building on the Secure Password Manager from the ICS0022 Secure Programming course, you will develop a web-based password manager focused on secure storage of credentials, user authentication, and preventing common web vulnerabilities. The password manager must ensure that user data is securely encrypted and protected against attacks such as SQL injection, XSS and CSRF.

You can get inspired by current password managers and how they handle passwords:
• NordPass: https://nordpass.com/
• 1Password: https://1password.com/
• Bitwarden: https://bitwarden.com/
• LastPass: https://www.lastpass.com/
• Passbolt: https://www.passbolt.com/

### 2. Requirements

The application must satisfy the following security requirements.
- Master password and authentication. A secure login system that protects the master password. Sessions must be securely managed, and multi-factor authentication may be offered as an option.
- Protection against SQL injection and XSS. Use prepared statements and parameterized queries to prevent SQL injection. Apply input validation and a Content Security Policy to prevent XSS.
- Session security and CSRF protection. Secure session management with secure cookies and expiration policies. CSRF tokens on all forms to prevent unauthorised actions.
- Access control. Enforce per-user ownership on every record operation.
- Error handling and logging. Generic user-facing errors that leak no stack traces or internals, and structured logging that never contains secrets.

### 3. Deliverables

The following deliverables are submitted at the end of the project.
- A working web-based password manager.
- Documentation on how to set up and use the system.
- A project report covering the encryption methods, authentication mechanisms and
security measures; how SQL injection and XSS are mitigated; and the testing results
demonstrating secure handling of credentials and prevention of attacks.
- Test cases and their results showing the functionality and security of the application.
