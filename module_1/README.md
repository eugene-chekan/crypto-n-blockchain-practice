# Module 1 - Modern Cryptography

## Task Overview
This module demonstrates modern cryptography techniques including symmetric key identification, AES decryption, elliptic curve key generation, and digital signature creation.

## Results

### 1. Correct Symmetric Key
**Key:** `54684020247570407220244063724074`
**SHA-256 Hash:** `f28fe539655fd6f7275a09b7c3508a3f81573fc42827ce34ddf1ec8d5c2421c3`

### 2. Decrypted Message
**Original Encrypted Data:** `876b4e970c3516f333bcf5f16d546a87aaeea5588ead29d213557efc1903997e`
**Decrypted Message:** `Hello Blockchain!`

### 3. Asymmetric Public Key
**Curve:** secp256r1 (P-256)
**Public Key (PEM format):**
```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETp0EdblBLIz2xxqIRD4FBq9Pw9JU
IBsyWJppsh67c0lVJPOjMZF58BYlV1CLEThMlUlOl0irqqXwvgGEiKrnGw==
-----END PUBLIC KEY-----
```

### 4. Digital Signature
**Message Signed:** `Hello Blockchain!`
**Signature Format:** DER
**Signature Size:** 71 bytes
**Signature (Hex):** `3045022100eafabaae0cfe2453400fddc33a6eda8a94d6be7e28c4b852a8675a61c8a06f9402202184b984cc4dcbcd1af988388bdbb72391e7c2ca2acc36bbd76d9915c56983b1`

## Step-by-Step Process

### Step 1: Symmetric Key Identification
- **Objective:** Find the correct 128-bit symmetric key from three candidates
- **Method:** Computed SHA-256 hash of each candidate key and compared with the target hash
- **Process:** Used the `key_finder.py` script to automatically test all three keys
- **Result:** Key #2 (`54684020247570407220244063724074`) matched the target hash

### Step 2: AES-128 Decryption
- **Objective:** Decrypt the AES-128-CBC encrypted message using the correct key
- **Method:** Applied AES-128-CBC decryption with the identified key and provided IV
- **Process:** Used the `aes_decrypt.py` script with:
  - Key: `54684020247570407220244063724074`
  - IV: `656e6372797074696f6e496e74566563`
  - Encrypted data: `876b4e970c3516f333bcf5f16d546a87aaeea5588ead29d213557efc1903997e`
- **Result:** Successfully decrypted to `Hello Blockchain!`

### Step 3: Elliptic Curve Key Generation
- **Objective:** Generate an asymmetric ECC key pair
- **Method:** Used secp256r1 (P-256) curve for key generation
- **Process:** Used the `ecc_keygen.py` script to generate a new key pair
- **Result:** Created both private and public keys in PEM format

### Step 4: Digital Signature Creation
- **Objective:** Create a digital signature over the decrypted plaintext message
- **Method:** Used ECDSA with SHA-256 hash algorithm
- **Process:** Used the `digital_signature.py` script to sign "Hello Blockchain!" with the generated private key
- **Result:** Created a 71-byte DER-encoded digital signature

## Technical Details

### Cryptographic Algorithms Used
- **Hash Function:** SHA-256 for key verification and digital signatures
- **Symmetric Encryption:** AES-128-CBC for message decryption
- **Asymmetric Cryptography:** ECDSA with secp256r1 curve
- **Digital Signature:** ECDSA with SHA-256 hash

### Security Considerations
- The symmetric key was identified through hash comparison, demonstrating the importance of secure key distribution
- AES-128-CBC was used with a proper initialization vector (IV)
- ECDSA provides strong digital signature capabilities with the secp256r1 curve
- All operations used industry-standard cryptographic libraries

## Files Generated
- `private_key.pem` - ECC private key
- `public_key.pem` - ECC public key  
- `signature.der` - Digital signature of the decrypted message

## Scripts Used
- `key_finder.py` - Symmetric key identification
- `aes_decrypt.py` - AES decryption
- `ecc_keygen.py` - ECC key pair generation
- `digital_signature.py` - Digital signature creation

## Source Code
All the source code is in the `module_1` folder of a GitHub repository.
You can find the repository [here](https://github.com/eugene-chekan/crypto-n-blockchain-practice/tree/main/module_1).
