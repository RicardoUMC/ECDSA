# ECDSA Implementation in C

This project is a C implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA), a widely used cryptographic algorithm for digital signatures. The implementation includes key generation, signing, and verification processes, and it uses PEM files for storing keys and signatures.

## Table of Contents
- [Requirements](#requirements)
- [Compilation](#compilation)
- [Usage](#usage)
  - [Key Generation](#key-generation)
  - [Signing a File](#signing-a-file)
  - [Verifying a Signature](#verifying-a-signature)
- [Example](#example)

## Requirements

To compile and run this project, you need the following:

- **GCC** (GNU Compiler Collection)
- **GMP** (GNU Multiple Precision Arithmetic Library)
- **OpenSSL** (for cryptographic functions and base64 encoding/decoding)

You can install these dependencies on a Debian-based system using:

```bash
sudo apt-get install build-essential libgmp-dev libssl-dev
```

## Compilation

To compile the project, navigate to the directory containing the source code and run:

```bash
gcc -o ecdsa ecdsa.c -lgmp -lcrypto
```

This will generate an executable named `ecdsa`.

## Usage

The program provides a menu-driven interface for key generation, signing, and verification. Below are the steps to use the program.

### Key Generation

1. Run the program:
   ```bash
   ./ecdsa
   ```
2. Select option `1` to generate a key pair.
3. Follow the prompts to enter the elliptic curve parameters (`p`, `a`, `b`, `q`) and the generator point `G`.
4. The program will generate a private key (`ecdsa_private_key.pem`) and a public key (`ecdsa_public_key.pem`).

### Signing a File

1. Run the program:
   ```bash
   ./ecdsa
   ```
2. Select option `2` to sign a file.
3. Enter the path to the file you want to sign.
4. The program will generate a signature file (`ecdsa_signature.txt`).

### Verifying a Signature

1. Run the program:
   ```bash
   ./ecdsa
   ```
2. Select option `3` to verify a signature.
3. Enter the path to the file you want to verify.
4. The program will check the signature against the file and the public key, and it will output whether the signature is valid or not.

## Example

Here is an example of how to use the program:

1. Generate keys:
   ```bash
   ./ecdsa
   ```
   - Select option `1`.
   - Enter the elliptic curve parameters and generator point.

2. Sign a file:
   ```bash
   ./ecdsa
   ```
   - Select option `2`.
   - Enter the path to the file you want to sign (e.g., `example.txt`).

3. Verify the signature:
   ```bash
   ./ecdsa
   ```
   - Select option `3`.
   - Enter the path to the file you want to verify (e.g., `example.txt`).
   - The program will output whether the signature is valid.

## Notes

- The private key is stored in `ecdsa_private_key.pem`, and the public key is stored in `ecdsa_public_key.pem`.
- The signature is stored in `ecdsa_signature.txt`.
- The program uses SHA-256 for hashing the files before signing or verifying.

This implementation is designed to be a practical example of how ECDSA works, and it can be used as a reference for understanding digital signatures in elliptic curve cryptography.
