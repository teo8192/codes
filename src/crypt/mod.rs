pub mod aes;
pub use aes::{AESKey, AES};

pub mod chacha20;
pub mod twofish;

/// Naive textbook implementation of RSA.
pub mod rsa;

pub mod sha;

/// Message authentication codes.
/// The keyed-hash MAC (HMAC) is implemented by [NIST FIPS 198-1](https://csrc.nist.gov/publications/detail/fips/198/1/final)
pub mod mac;

/// The encryption mode.
/// Should add more modes from [NIST SP 800 38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
#[derive(Copy, Clone)]
pub enum EncryptionMode {
    CBC, //< Cipher Block Chaining, input vectors should be unpredictable and not reused.
    ECB, //< Electronic Codebook mode, You should rather use CBC or something
}

pub trait Cipher {
    fn encrypt(&self, iv: &[u8], plaintext: &mut [u8]) -> Result<(), String>;

    fn decrypt(&self, iv: &[u8], ciphertext: &mut [u8]) -> Result<(), String>;
}

/// Any block cipher implementingthis trait may be used with the implementation of CBC.
pub trait BlockCipher {
    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);

    /// Block size of the cipher
    fn block_size(&self) -> usize;

    /// The selected encryption mode
    fn encryption_mode(&self) -> EncryptionMode {
        EncryptionMode::CBC
    }

    /// Change the encryption mode.
    fn change_encryption_mode(&mut self, _mode: EncryptionMode) {}
}

impl dyn BlockCipher {
    /// Encrypt bytes in CBC mode.
    /// It will always add padding.
    fn cbc_encrypt(&self, iv: &[u8], plaintext: &mut [u8]) -> Result<(), String> {
        if iv.len() != self.block_size() {
            return Err(format!(
                "input vector is wrong length, expected {}, got {}",
                self.block_size(),
                iv.len()
            ));
        }
        let bs = self.block_size();
        let prev_block: &mut [u8] = &mut iv.to_vec();

        // pad(plaintext, bs);

        for i in 0..plaintext.len() / bs {
            for (pltxt, prev) in plaintext[(i * bs)..((i + 1) * bs)]
                .iter_mut()
                .zip(prev_block.iter())
            {
                *pltxt ^= *prev;
            }

            self.encrypt_block(&mut plaintext[(i * bs)..((i + 1) * bs)]);

            for j in 0..bs {
                prev_block[j] = plaintext[(i * bs) + j];
            }
        }
        Ok(())
    }

    /// Decrypt bytes that was encrypted in CBC mode
    fn cbc_decrypt(&self, iv: &[u8], ciphertext: &mut [u8]) -> Result<(), String> {
        let bs = self.block_size();

        if iv.len() != bs {
            return Err(format!(
                "input vector is wrong length, expected {}, got {}",
                bs,
                iv.len()
            ));
        }
        if ciphertext.len() % bs != 0 {
            return Err(format!(
                "ciphertext length ({}) should be a multiple of the blocksize ({})",
                ciphertext.len(),
                bs,
            ));
        }
        let prev_block: &mut [u8] = &mut iv.to_vec();

        for i in 0..(ciphertext.len() / bs) {
            let current_block = &mut ciphertext[(i * bs)..((i + 1) * bs)];

            // save the current ciphertext to remove
            // the chaining of the next block
            let pb = prev_block.to_vec();

            prev_block[..bs].clone_from_slice(&current_block[..bs]);

            // decrypt current block
            self.decrypt_block(current_block);

            // Reverse the chaining
            for (cur, prev) in current_block.iter_mut().zip(pb.iter()) {
                *cur ^= *prev;
            }
        }

        // strip_padding(ciphertext);

        Ok(())
    }

    fn ecb_encrypt(&self, _: &[u8], plaintext: &mut [u8]) -> Result<(), String> {
        let bs = self.block_size();

        // pad(plaintext, bs);

        for i in 0..plaintext.len() / bs {
            self.encrypt_block(&mut plaintext[(i * bs)..((i + 1) * bs)]);
        }

        Ok(())
    }

    fn ecb_decrypt(&self, _: &[u8], ciphertext: &mut [u8]) -> Result<(), String> {
        let bs = self.block_size();

        if ciphertext.len() % bs != 0 {
            return Err(format!(
                "ciphertext length ({}) should be a multiple of the blocksize ({})",
                ciphertext.len(),
                bs,
            ));
        }

        for i in 0..(ciphertext.len() / bs) {
            // decrypt current block
            self.decrypt_block(&mut ciphertext[(i * bs)..((i + 1) * bs)]);
        }

        // strip_padding(ciphertext);

        Ok(())
    }
}

pub fn pad(bytes: &mut Vec<u8>, bs: usize) {
    let len: u32 = bytes.len() as u32;
    let end_bytes: u32 = 32 >> 3;
    let zeros = bs - ((end_bytes + len + 1) as usize % bs);

    // The leading one
    let one = [1u8 << 7].iter();

    // the number at the end
    let end_num = (zeros as u32 + end_bytes + 1).to_le_bytes();

    // Has to be repeated reference to 0 since the other iterators operate on &u8
    let zeros = std::iter::repeat(&0u8).take(zeros);

    // append a one, a lot of zeros and then the number of padded bytes
    // ends up something like this:
    // 1 0 0 0 0 0 0 0 0 0 0 12
    bytes.append(&mut one.chain(zeros).chain(end_num.iter()).cloned().collect());
}

pub fn strip_padding(bytes: &mut Vec<u8>) {
    let mut end = [0u8; 4];
    let offset = bytes.len() - std::mem::size_of::<u32>();

    end[..4].clone_from_slice(&bytes[offset..(4 + offset)]);

    // Get the number at the end
    let end = u32::from_le_bytes(end) as usize;

    // Drain the padding from the vector
    bytes.drain((bytes.len() - end)..bytes.len());
}

impl Cipher for dyn BlockCipher {
    fn encrypt(&self, iv: &[u8], plaintext: &mut [u8]) -> Result<(), String> {
        if plaintext.len() % self.block_size() != 0 {
            return Err(format!("You should consider padding your messages."));
        }
        use EncryptionMode::*;
        match self.encryption_mode() {
            CBC => self.cbc_encrypt(iv, plaintext),
            ECB => self.ecb_encrypt(iv, plaintext),
        }
    }

    fn decrypt(&self, iv: &[u8], ciphertext: &mut [u8]) -> Result<(), String> {
        use EncryptionMode::*;
        match self.encryption_mode() {
            CBC => self.cbc_decrypt(iv, ciphertext),
            ECB => self.ecb_decrypt(iv, ciphertext),
        }
    }
}

fn pbkdf2_round(password: &[u8], salt: &[u8], count: usize, i: usize) -> Box<[u8; 32]> {
    let mut result = Box::new([0u8; 32]);
    let mut k = salt.to_owned();
    k.append(&mut format!("{}", i).into_bytes());
    let mut tmp_0 = mac::hmac(&password.to_owned(), &k, 32);
    for _ in 1..count {
        let tmp = mac::hmac(&password.to_owned(), &tmp_0, 32);
        for (i, b) in tmp.iter().enumerate() {
            result[i] ^= b;
        }
        tmp_0 = tmp;
    }
    result
}

/// password based key derivation funcrion v. 2.1
/// Implemented by [RFC8018](https://tools.ietf.org/html/rfc8018)
/// Applies a pseudo-random function a lot of times to the password and salt to generate a key.
///
///  - password is the password
///  - salt is a salt
///  - dklen is the derived key length in bits
///  - c is the iteration count
pub fn pbkdf2(password: &[u8], salt: &[u8], c: usize, dklen: usize) -> Vec<u8> {
    debug_assert!(dklen <= ((1 << 32) - 1) * 256, "derived key too long");
    let l = dklen / 256 + if dklen % 256 != 0 { 1 } else { 0 };
    let mut res = Vec::new();
    let mut counter = 0;
    'outer: for block in (0..l).map(|i| pbkdf2_round(password, salt, c, i)) {
        for b in block.iter() {
            if counter * 8 >= dklen {
                break 'outer;
            }
            res.push(*b);
            counter += 1;
        }
    }

    res
}
