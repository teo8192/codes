# Future problems that require future solutions

 - [x] Input vector be removed from aes cipher and inv_cipher.
 - [x] Encrypt and decrypt not aligned with 16 bytes.
 - [x] IV in encrypt and decrypt iterator.
 - [x] cipher block chaining in encrypt and decrypt iterator.
 - [x] cipher text stealing in encrypt and decrypt iterator.

 - [ ] Incorporate the code of Frixxie

# BUGS

 - [ ] Encrypt and decrypt stream is buggy when encrypting less than a single block. (CTS should not be activated, but i think maybe it is?)
