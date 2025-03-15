# Brain Wallet

This project is a C implementation of a brain wallet that generates Bitcoin addresses (including P2PKH, P2SH, Bech32, and Bech32m) from a user-provided passphrase. The program utilizes the secp256k1 elliptic curve and includes implementations of SHA256, RIPEMD160, Base58, Base58Check, and Bech32/Bech32m encoding/decoding.  This project demonstrates the complete process of deriving public keys and various Bitcoin address formats from a private key.

## Features

*   **Passphrase to Private Key:** Generates a private key by hashing a user-provided passphrase using SHA256.
*   **Private Key Formats:** Converts the private key into both compressed and uncompressed Wallet Import Format (WIF).
*   **Elliptic Curve Cryptography:** Performs scalar multiplication on the secp256k1 curve to derive the corresponding public key from the private key.
*   **Public Key Formats:** Generates both compressed and uncompressed public key strings.
*   **Hash Functions:** Includes implementations of SHA256 and RIPEMD160 for hashing operations (hash160).
*   **Address Generation:** Generates various Bitcoin address types:
    *   **P2PKH:** Pay-to-Public-Key-Hash (legacy addresses starting with '1').
    *   **P2SH:** Pay-to-Script-Hash (addresses starting with '3'). This implementation generates P2SH addresses wrapping P2PKH scripts.
    *   **P2SH-P2WPKH:** P2SH wrapped Pay-to-Witness-Public-Key-Hash (addresses starting with '3').
    *   **Bech32:** Native SegWit addresses (starting with 'bc1q').
    *   **Bech32m:** Addresses for Taproot and future SegWit versions (starting with 'bc1p').
    *   **P2WSH:** Pay-to-Witness-Script-Hash (Bech32 addresses starting with 'bc1', where the witness script is a P2PKH script).
    *   **P2WSH-P2WPKH:** P2WSH wrapping a P2WPKH script.
*   **Clear Output:** Displays intermediate values (private key in hex, WIF, public keys, hash160) and all generated addresses.

## Dependencies

*   **GMP (GNU Multiple Precision Arithmetic Library):** Used for large integer arithmetic required by elliptic curve operations.  You'll need to install this library.
    *   Ubuntu/Debian:  `sudo apt-get install libgmp-dev`
    *   Fedora/CentOS/RHEL:  `sudo yum install gmp-devel`
    *   macOS (using Homebrew): `brew install gmp`

*   **Standard C Libraries:**  `stdio.h`, `stdlib.h`, `stdint.h`, `stdbool.h`, `string.h`, `unistd.h`, `time.h`

*   **Included Libraries:** The project includes self-contained implementations of the following in separate directories, which are linked during compilation:
    *   `ecc/`: Elliptic Curve Cryptography functions (secp256k1).
    *   `sha256/`: SHA256 hashing.
    *   `ripemd160/`: RIPEMD160 hashing.
    *   `base58/`: Base58 encoding/decoding.
    *   `bech32/`: Bech32 and Bech32m encoding/decoding.
    *   `customutil/`: Custom utility functions, including public key string generation.

### Compilation

The project provides several methods for compilation, including a Makefile, a CMake build system, and a simple GCC command. Choose *one* of the following:

### 1. Using Makefile (Recommended)

A `Makefile` is included for easy compilation.  From the project's root directory, simply run:

```
make

```

### 2. Using CMake

A CMakeLists.txt file is also included for use with CMake.
```bash
mkdir build
cd build
cmake ..
make

```

### 3. Using GCC (Single Command)

Alternatively, you can compile the program with the following GCC command (ensure you are in the project's root directory):
```
gcc -O3 -o Brain Brain.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c ecc/ecc.c customutil/customutil.c -lgmp
```


### This command uses the -O3 optimization flag, which can generate more efficient executable code.

Usage

After compiling, run the program with a passphrase as a command-line argument:
```
./Brain "you are so sexy"
```
or
```
./Brain you are so sexy
Password Phrase: you are so sexy
SHA256 Hash (passphrase Hex): a299e70c5dcec3357eb6beffe71206f63580f7217adab656fffc217df95fa484
WIF Private Key (Compressed): L2fnZUEo3pjdzGNZdRwBV7m3tR3LLrXGh9xvkh8U9JEHkZcn9vTj
WIF Private Key (Uncompressed): 5K3u1ZTEc5ULFnd9kbeeiiQaHBRzrMjezakV3CMiwtwDQU7epGh

Compressed Public Key: 037966a6973797d78d29d14fa3251591e14afde3aea2de3a009b69088077314087
Uncompressed Public Key: 047966a6973797d78d29d14fa3251591e14afde3aea2de3a009b69088077314087ad89223cc28f9b2d32b4fc4702c709db4cd362a927df399e094fdd726e2b5557
Compressed Public Key Hash160: a297dc14a08bac02f0a06f11543a2fd54f960e4a
Uncompressed Public Key Hash160: dc9ec1d260a040058d50d7d0dcfa28df9ca9b020

=== Addresses Generated from Compressed Public Key ===
P2PKH (Starts with 1) Address (Compressed): 1FpiPURLAzXfsfmAvdpnkBCjAYPeZjXHfr
P2SH (Starts with 3) Address (Compressed): 3GWjK1umitr3xqTc3jVPAoZfK4gN6xZv3r (P2SH => P2PKH)
P2SH (Starts with 3) Address (Compressed): 3E9EA5mfkzccKceR7TbawBtaoeKfGB4oni (P2SH => P2WPKH)
Bech32 (Starts with bc1) Address (Compressed): bc1q52tac99q3wkq9u9qdug4gw30648evrj2vefgv2
Bech32m (Starts with bc1p) Address (Compressed): bc1p52tac99q3wkq9u9qdug4gw30648evrj2887rpp
P2WSH (Starts with bc1) Address (Compressed): bc1qvyhwjp25wsmkcnxynh9cjmgwjq96hayc0mapev24dlf78mpyd2vq90zhk0 (P2WSH => P2PKH)
P2WSH (Starts with bc1) Address (Compressed): bc1qxh0383g9qa7zk6lpf4qc5d636svryhtcxm35ze3y59crut638vvqukrca3 (P2WSH => P2WPKH)

=== Addresses Generated from Uncompressed Public Key ===
P2PKH (Starts with 1) Address (Uncompressed): 1M7XqqkVuLJLrcYQnWRM3hLvc6nejCaBnp
P2SH (Starts with 3) Address (Uncompressed): 3MoYmPEwTEciwnEquc5wUKhrkd5NHYoBPb (P2SH => P2PKH)
P2SH (Starts with 3) Address (Uncompressed): 3NiRVs2i3yxYzEcTtHgQfTtS7CdPufeE5J (P2SH => P2WPKH)
Bech32 (Starts with bc1) Address (Uncompressed): bc1qmj0vr5nq5pqqtr2s6lgde73gm7w2nvpqrvncxd
Bech32m (Starts with bc1p) Address (Uncompressed): bc1pmj0vr5nq5pqqtr2s6lgde73gm7w2nvpqgjyntx
P2WSH (Starts with bc1) Address (Uncompressed): bc1qplhqcuzeg0m5wy62l9dxpz8hffm90jkpjrke0w83gdwwnyzpg7qswr3fxy (P2WSH => P2PKH)
P2WSH (Starts with bc1) Address (Uncompressed): bc1q5yxe627fp04wjwqccxck5qh3sz2gnq8v6hww0vz5ffuvg4cyafrswxxtku (P2WSH => P2WPKH)

```

### Code Structure
```
Brain.c: The main program file. Handles command-line arguments, calls the address generation functions, and prints the results.

ecc/ecc.h and ecc/ecc.c: Implements elliptic curve operations over the secp256k1 curve using the GMP library.

sha256/sha256.h and sha256/sha256.c: Implementation of the SHA256 hash algorithm.

ripemd160/ripemd160.h and ripemd160/ripemd160.c: Implementation of the RIPEMD160 hash algorithm.

base58/base58.h and base58/base58.c: Implementation of Base58 and Base58Check encoding/decoding.

bech32/bech32.h and bech32/bech32.c: Implementation of Bech32 and Bech32m encoding/decoding.

customutil/customutil.h and customutil/customutil.c: Contains the generate_strpublickey function, which converts a Point structure (representing an elliptic curve point) into its hexadecimal string representation (compressed or uncompressed). It also has other utility functions that might be helpful for debugging and development, like print_hex, but those aren't directly used in the address generation process.
```
### Security Considerations

Passphrase Strength: The security of the generated addresses depends entirely on the strength of the passphrase. Use a strong, randomly generated passphrase.

Library Dependencies: This project uses the GMP library for arbitrary-precision arithmetic. Make sure you are using a trusted and up-to-date version of GMP.

Randomness: The included code doesn't explicitly use a cryptographically secure random number generator for key generation because the private key is derived directly from the SHA256 hash of the passphrase. If you were to modify this code to generate random private keys directly, you must use a cryptographically secure PRNG (e.g., /dev/urandom on Linux/macOS).

Side-Channel Attacks: This code has not been hardened against side-channel attacks (e.g., timing attacks).

### Sponsorship
If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!
```
-BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
-
-ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
-
-DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
-
-TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
-
```
