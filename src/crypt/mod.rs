/// The Advanced Encryption Standard, according to NIST FIPS 197
pub mod aes;
pub use aes::{AESKey, AES};

/// Naive textbook implementation of RSA.
pub mod rsa;

/// Currently SHA512 implemented by FIPS 180-4 standard.
pub mod sha;

pub mod pbkdf2;

pub mod mac;

/// Any block cipher implementingthis trait may be used with the implementation of CBC with CTS.
pub trait BlockCipher {
    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);
    fn block_size(&self) -> usize; // Block size takes self, in case it is dependent on key (e.g. vignere cipher)

    fn cbc_encrypt(&self, iv: &Vec<u8>, plaintext: &mut Vec<u8>) -> Result<(), String> {
        if iv.len() != self.block_size() {
            return Err(format!(
                "input vector is wrong length, expected {}, got {}",
                self.block_size(),
                iv.len()
            ));
        }
        let len: u32 = plaintext.len() as u32;
        let blocksize = self.block_size();
        let end_bytes = 32 >> 3;
        let zeros = blocksize - ((end_bytes + len as usize + 1) % blocksize);
        plaintext.push(1);
        for _ in 0..zeros {
            plaintext.push(0);
        }
        plaintext.append(&mut ((zeros + end_bytes + 1) as u32).to_le_bytes().to_vec());

        let mut prev_block: Vec<u8> = iv.clone();

        for i in 0..plaintext.len() / blocksize {
            for j in 0..blocksize {
                plaintext[i * blocksize + j] ^= prev_block[j];
            }

            self.encrypt_block(&mut plaintext[(i * blocksize)..((i + 1) * blocksize)]);

            for j in 0..blocksize {
                prev_block[j] = plaintext[(i * blocksize) + j];
            }
        }
        Ok(())
    }

    fn cbc_decrypt(&self, iv: &Vec<u8>, ciphertext: &mut Vec<u8>) -> Result<(), String> {
        if iv.len() != self.block_size() {
            return Err(format!(
                "input vector is wrong length, expected {}, got {}",
                self.block_size(),
                iv.len()
            ));
        }
        if ciphertext.len() % self.block_size() != 0 {
            return Err(format!(
                "ciphertext length ({}) should be a multiple of the blocksize ({})",
                ciphertext.len(),
                self.block_size(),
            ));
        }

        let bs = self.block_size();
        let mut prev_block = Vec::new();
        for i in iv {
            prev_block.push(*i);
        }

        let mut end = [0u8; 4];

        for i in 0..(ciphertext.len() / bs) {
            let curb = &ciphertext[(i * bs)..((i + 1) * bs)];
            let pb = prev_block.clone();
            for i in 0..bs {
                prev_block[i] = curb[i];
            }

            self.decrypt_block(&mut ciphertext[(i * bs)..((i + 1) * bs)]);
            for j in 0..self.block_size() {
                ciphertext[(i * bs) + j] ^= pb[j];
            }
        }

        for i in 0..4 {
            end[i] = ciphertext[i + ciphertext.len() - std::mem::size_of::<u32>()];
        }

        let end = u32::from_le_bytes(end);

        for _ in 0..end {
            let i = ciphertext.len() - 1;
            ciphertext[i] = 0;
            ciphertext.pop();
        }

        Ok(())
    }
}
