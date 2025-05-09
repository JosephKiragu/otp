# ft_otp: Time-based One-Time Password Implementation

A secure implementation of TOTP (Time-based One-Time Password) based on RFC 6238 and RFC 4226.

## Overview

This project implements a TOTP (Time-based One-Time Password) system capable of generating ephemeral passwords from a master key. It follows the standards defined in:
- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) (TOTP)
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) (HOTP)

## Features

- **Generation of secure cryptographic keys**
- **Key validation with entropy checking**
- **Secure encryption of keys using AES-256-CBC**
- **HMAC-SHA1 implementation for HOTP**
- **Time-based extension for TOTP**
- **Constant-time comparison to prevent timing attacks**
- **Proper memory management for sensitive data**

## Security Considerations

- Keys are encrypted before being stored on disk
- Sensitive data is cleared from memory when no longer needed
- Protection against timing attacks using constant-time comparison
- Key entropy validation to ensure strong keys
- Error handling that doesn't leak sensitive information

## Requirements

- OpenSSL library (libssl-dev)
- GCC or compatible C compiler
- Make

## Installation

```bash
make all
```

This will compile the program and create the executable `ft_otp` in the project directory.

## Usage

### Generating and Storing a Key

Generate a hexadecimal key of at least 64 characters and store it securely:

```bash
./ft_otp -g key.hex
```

The key will be encrypted and stored in `ft_otp.key`.

### Generating a One-Time Password

Generate a one-time password using the stored key:

```bash
./ft_otp -k ft_otp.key
```

The program will output a 6-digit one-time password that changes based on the current time.

## Error Handling

Error messages for various scenarios:

- Invalid key format
- File access issues
- Encryption/decryption errors
- Memory allocation failures
- Time-related failures

## Project Structure

- **include/ft_otp.h**: Header file with function declarations and constants
- **src/crypto.c**: Cryptographic operations (HMAC-SHA1)
- **src/hotp.c**: HOTP algorithm implementation
- **src/totp.c**: TOTP algorithm implementation
- **src/key_management.c**: Key validation, encryption, and storage
- **src/mem_error.c**: Memory allocation and error handling
- **src/main.c**: Main program and tests

## Implementation Details

### HOTP Algorithm (RFC 4226)

The HOTP algorithm generates a one-time password based on:
1. A shared secret key
2. A counter value

The algorithm uses HMAC-SHA1 to produce a 20-byte value, which is then truncated to produce a 6-8 digit code.

### TOTP Extension (RFC 6238)

TOTP extends HOTP by using time as the counter value:
1. Current time is divided by a time step (default 30 seconds)
2. The resulting value is used as the counter for HOTP

### Key Management

Keys are:
1. Validated for sufficient entropy
2. Encrypted using AES-256-CBC with a derived key (PBKDF2)
3. Stored securely with proper file permissions


## Testing

Run the included tests to verify the implementation:

```bash
./ft_otp -t
```

## License

This project is released under the MIT License.
