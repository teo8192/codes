# About

This is a cryptographic library (mostly made for fun and academic purpose).
I try to adhere to standards, and verify the implementation by expected output.
Here is some of the resources used:

 - For tests: [Cryptographic Standards and Guidelines, Examples with Intermediate Values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)
 - AES, [NIST FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final)
 - Secure Hashing Algorithm (SHA) [NIST FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)
 - PBKDF2: [RFC8018](https://tools.ietf.org/html/rfc8018)


# Stuff to implement

 - [ ] SHA256 fam
 - [ ] SHA3
 - [ ] CMAC
 - [ ] Elliptic curves
 - [ ] Message padding like SHA512 for CBC
 - [ ] CBC in place on mutable vector

# Future problems that require future solutions

 - [x] Input vector be removed from aes cipher and inv_cipher.
 - [x] Encrypt and decrypt not aligned with 16 bytes.
 - [x] IV in encrypt and decrypt iterator.
 - [x] cipher block chaining in encrypt and decrypt iterator.
 - [x] cipher text stealing in encrypt and decrypt iterator.

 - [ ] Incorporate the code of Frixxie

# BUGS

 - [ ] Encrypt and decrypt stream is buggy when encrypting less than a single block. (CTS should not be activated, but i think maybe it is?)
