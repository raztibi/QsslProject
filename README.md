# Quantum-Resistant Banking Communication System

![Bank Vault](qsslWPF/Resources/vault.jpg)

## Overview
A proof-of-concept banking system implementing quantum-resistant cryptography alongside traditional encryption methods. The system combines RSA with Kyber for key exchange, and uses both ECC and Dilithium for digital signatures, providing hybrid classical-quantum protection.

## Key Features
- Hybrid key exchange using RSA and Kyber
- Dual signature system with ECC and Dilithium
- AES session key generation using XOR of RSA and Kyber outputs
- WPF-based banking interface
- Client-server architecture with secure communication

## Prerequisites
- OpenSSL library required
- Download from: https://openssl-library.org/source/

## Installation
1. Install OpenSSL from the provided link
2. Build the solution
3. Executables will be generated in `out/build/x64-Debug/tests`

## Usage
1. Run server.exe
2. Wait for server initialization
3. Run client.exe
4. Use the WPF interface for banking operations

## ⚠️ Warning
This project is experimental and should not be used until the quantum algorithms will be proven as fully safe. The writers are not responsible for any use of the software.

## Architecture
```
Client <-> GUI
  ↓
Encryption Layer (RSA + Kyber)
  ↓
Signature Layer (ECC + Dilithium)
  ↓
Server
```

## Acknowledgments
Special thanks to the openQssl team for their invaluable library and support.

## Authors
- Matan Czcuckermann
- Raz Tibi

## License
This project is licensed under the MIT License