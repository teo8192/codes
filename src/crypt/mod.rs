/// The Advanced Encryption Standard, according to NIST FIPS 197
pub mod aes;
pub use aes::{AESKey, AES};

/// Naive textbook implementation of RSA.
pub mod rsa;

/// Currently SHA512 implemented by FIPS 180-4 standard.
pub mod sha;

use std::collections::VecDeque;

/// Encrypt and decrypt iterators of data.
///
/// C is a cipher.
///
/// I is the item in the iterator.
///
/// E is the encryptor structure.
/// It needs to be an iterator itself.
///
/// D is the decryptor structure.
/// It also needs to be an iterator.
pub trait Crypt<'a, 'b, C, I, E: Iterator<Item = I>, D: Iterator<Item = I>>:
    Iterator<Item = I>
{
    /// Take a cipher and return an encrypted iterator.
    fn encrypt(&'a mut self, crypt: &'b C, iv: Vec<u8>) -> E;
    /// Take a cipher and return a decrypted iterator.
    fn decrypt(&'a mut self, crypt: &'b C, iv: Vec<u8>) -> D;
}

/// Any block cipher implementingthis trait may be used with the implementation of CBC with CTS.
pub trait BlockCipher {
    fn encrypt_block(&self, block: Vec<u8>) -> Vec<u8>;
    fn decrypt_block(&self, block: Vec<u8>) -> Vec<u8>;
    fn block_size(&self) -> usize; // Block size takes self, in case it is dependent on key (e.g. vignere cipher)
}

/// The block encryptor struct that is returned when encrypting an iterator.
pub struct CBCCTSEncryptor<'a, 'b, I: Iterator<Item = u8>, C: BlockCipher> {
    iterator: &'a mut I,
    encrypted: VecDeque<u8>,
    next_block: Option<Vec<u8>>,
    iv: Vec<u8>,
    cipher: &'b C,
}

impl<'a, 'b, I: Iterator<Item = u8>, C: BlockCipher> CBCCTSEncryptor<'a, 'b, I, C> {
    fn encrypt_next_block(&mut self) {
        let mut block: Vec<u8> = self.iterator.take(self.cipher.block_size()).collect();
        let leave = block.len(); //< how many bytes top leave in the next block

        if leave == 0 {
            if let Some(next) = &self.next_block {
                for b in next {
                    self.encrypted.push_back(*b);
                }
                self.next_block = None;
            }
            return;
        }

        if leave < self.cipher.block_size() {
            block.append(
                &mut std::iter::repeat(0u8)
                    .take(self.cipher.block_size() - leave)
                    .collect(),
            );
        }

        if let Some(next) = &self.next_block {
            for i in 0..self.cipher.block_size() {
                block[i] ^= next[i];
            }
            let block = self.cipher.encrypt_block(block);
            self.next_block = if leave == self.cipher.block_size() {
                for b in next {
                    self.encrypted.push_back(*b);
                }
                Some(block)
            } else {
                let mut vec = block.to_vec();
                vec.append(&mut next.to_vec().into_iter().take(leave).collect());
                self.encrypted.append(&mut VecDeque::from(vec));
                None
            };
        } else {
            // this is the first time, so bootstrap that motherfucker
            for i in 0..self.cipher.block_size() {
                block[i] ^= self.iv[i];
            }
            let block = self.cipher.encrypt_block(block);
            self.next_block = Some(block);
            self.encrypt_next_block();
        }
    }
}

impl<'a, 'b, I: Iterator<Item = u8>, C: BlockCipher> Iterator for CBCCTSEncryptor<'a, 'b, I, C> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        if self.encrypted.len() == 0 {
            self.encrypt_next_block();
        }
        self.encrypted.pop_front()
    }
}

/// Decrypt an encrypted byte stream.
///
/// Here AES is used as an example.
///
///     # use codes::crypt::{Crypt, AES, AESKey, BlockCipher};
///     # let plaintext = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.".to_vec();
///     # let mut key = [0u8;32];
///     # let mut seed = 3422334usize;
///     # for i in 0..32 {
///         # key[i] = seed as u8 & 255;
///         # seed += i;
///         # seed *= 1234;
///         # seed >>= 10;
///     # }
///     let aes = AES::new(AESKey::AES256(key));
///     # let encrypted: Vec<u8> = plaintext
///     #       .into_iter()
///     #       .encrypt(&aes, (0..16).collect())
///     #       .collect();
///     # let iv = (0..16).collect();
///     let decrypted: Vec<u8> = encrypted
///         .into_iter()
///         .decrypt(&aes, iv)
///         .collect();
///     assert_eq!(decrypted, b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.".to_vec());
pub struct CBCCTSDecryptor<'a, 'b, I: Iterator<Item = u8>, C: BlockCipher> {
    iterator: &'a mut I,
    decrypted: VecDeque<u8>,
    current_block: Vec<u8>,
    next_block: Option<Vec<u8>>,
    cipher: &'b C,
}

impl<'a, 'b, I: Iterator<Item = u8>, C: BlockCipher> CBCCTSDecryptor<'a, 'b, I, C> {
    fn decrypt_next_block(&mut self) {
        let mut block: Vec<u8> = self.iterator.take(self.cipher.block_size()).collect();
        let leave = block.len();
        // If it is at the end (not able to take any bytes from the input)
        if leave == 0 {
            if let Some(block) = &self.next_block {
                // decrypt and apply the IV
                let decrypted = self.cipher.decrypt_block(block.clone());
                for i in 0..self.cipher.block_size() {
                    self.decrypted
                        .push_back(decrypted[i] & self.current_block[i])
                }
                self.next_block = None;
            }
            return;
        }

        if leave != self.cipher.block_size() {
            if let Some(next) = &self.next_block {
                let mut decrypted = Vec::from(self.cipher.decrypt_block(next.clone()));

                block.append(&mut decrypted.drain(leave..self.cipher.block_size()).collect());

                for i in 0..leave {
                    decrypted[i] ^= block[i];
                }

                let omega2decr = self.cipher.decrypt_block(block);
                for i in 0..self.cipher.block_size() {
                    self.decrypted
                        .push_back(omega2decr[i] ^ self.current_block[i]);
                }
                for b in decrypted {
                    self.decrypted.push_back(b);
                }

                self.next_block = None;
            } else {
                block.append(
                    &mut std::iter::repeat(0)
                        .take(self.cipher.block_size() - leave)
                        .collect(),
                );
                let decr = self.cipher.decrypt_block(block);
                for b in decr {
                    self.decrypted.push_back(b)
                }
            }
            return;
        }

        if let Some(nblock) = &self.next_block {
            // decrypt and apply the IV
            let mut decrypted = self.cipher.decrypt_block(nblock.clone());
            for i in 0..self.cipher.block_size() {
                decrypted[i] ^= self.current_block[i];
            }

            // append the decrypted bytes
            self.decrypted
                .append(&mut VecDeque::from(decrypted.to_vec()));

            // set up for next iteration
            self.current_block = nblock.clone();
            self.next_block = Some(block);
        } else {
            // Bootstrap if the next bytes is none
            self.next_block = Some(block);
            self.decrypt_next_block();
        }
    }
}

impl<'a, 'b, I: Iterator<Item = u8>, C: BlockCipher> Iterator for CBCCTSDecryptor<'a, 'b, I, C> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        // If there is no available bytes, get more
        if self.decrypted.len() == 0 {
            self.decrypt_next_block();
        }
        // Pop the front, if the queue is emty, returns none (the iterator is exhausted)
        self.decrypted.pop_front()
    }
}

impl<'a, 'b, I: Iterator<Item = u8>, C: BlockCipher>
    Crypt<'a, 'b, C, u8, CBCCTSEncryptor<'a, 'b, I, C>, CBCCTSDecryptor<'a, 'b, I, C>> for I
{
    /// Encrypt a byte stream that is encrypted with a block cipher with CBC format and using CTS.
    /// CBC: [Cipher Block Chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
    ///
    /// with CTS the end is special.
    /// Id the bytes at the end does not align to the block size, the missing bytes is borrowed
    /// from the previous block.
    /// this is archieved  by setting the ending bytes to 0 and using the IV xor operation as
    /// usual. this means that the ending bytes from the next to last block is removed (since they
    /// can be found by decrypting the last block) and the next to last partial block is placed at
    /// the end of the byte iterator, so they swap places (the swap is not neccecary, it is just
    /// the way this implementation works).
    fn encrypt(&'a mut self, crypt: &'b C, iv: Vec<u8>) -> CBCCTSEncryptor<'a, 'b, I, C> {
        CBCCTSEncryptor {
            iterator: self,
            encrypted: VecDeque::new(),
            next_block: None,
            iv,
            cipher: crypt,
        }
    }

    /// Decrypt a byte stream that is encrypted with a block cipher with CBC format and using CTS.
    fn decrypt(&'a mut self, crypt: &'b C, iv: Vec<u8>) -> CBCCTSDecryptor<'a, 'b, I, C> {
        CBCCTSDecryptor {
            iterator: self,
            decrypted: VecDeque::new(),
            current_block: iv, //vec![0; crypt.block_size()],
            next_block: None,
            cipher: crypt,
        }
    }
}
