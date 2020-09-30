/// The Advanced Encryption Standard, according to NIST FIPS 197
pub mod aes;
pub use aes::{AESKey, AES};

/// Naive textbook implementation of RSA.
pub mod rsa;

/// Currently SHA512 implemented by FIPS 180-4 standard.
pub mod sha;

pub mod pbkdf2;

pub mod mac;

pub enum EncryptionMode {
    CBC,
}

fn pad(bytes: &mut Vec<u8>, bs: usize) {
    let len: u32 = bytes.len() as u32;
    let end_bytes: u32 = 32 >> 3;
    let zeros = bs - ((end_bytes + len + 1) as usize % bs);

    // The leading one
    let one = [1u8].iter();

    // the number at the end
    let end_num = (zeros as u32 + end_bytes + 1).to_le_bytes();

    // Has to be repeated reference to 0 since the other iterators operate on &u8
    let zeros = std::iter::repeat(&0u8).take(zeros);

    // append a one, a lot of zeros and then the number of padded bytes
    // ends up something like this:
    // 1 0 0 0 0 0 0 0 0 0 0 12
    bytes.append(&mut one.chain(zeros).chain(end_num.iter()).map(|x| *x).collect());
}

fn strip_padding(bytes: &mut Vec<u8>) {
    let mut end = [0u8; 4];
    let offset = bytes.len() - std::mem::size_of::<u32>();

    for i in 0..4 {
        end[i] = bytes[i + offset];
    }

    // Get the number at the end
    let end = u32::from_le_bytes(end) as usize;

    // Drain the padding from the vector
    bytes.drain((bytes.len() - end)..bytes.len());
}

/// Encrypt bytes in CBC mode.
/// It will always add padding.
fn cbc_encrypt<B: BlockCipher>(
    cipher: &B,
    iv: &Vec<u8>,
    plaintext: &mut Vec<u8>,
) -> Result<(), String> {
    if iv.len() != cipher.block_size() {
        return Err(format!(
            "input vector is wrong length, expected {}, got {}",
            cipher.block_size(),
            iv.len()
        ));
    }
    let bs = cipher.block_size();
    let mut prev_block: Vec<u8> = iv.clone();

    pad(plaintext, bs);

    for i in 0..plaintext.len() / bs {
        for j in 0..bs {
            plaintext[i * bs + j] ^= prev_block[j];
        }

        cipher.encrypt_block(&mut plaintext[(i * bs)..((i + 1) * bs)]);

        for j in 0..bs {
            prev_block[j] = plaintext[(i * bs) + j];
        }
    }
    Ok(())
}

/// Decrypt bytes that was encrypted in CBC mode
fn cbc_decrypt<B: BlockCipher>(
    cipher: &B,
    iv: &Vec<u8>,
    ciphertext: &mut Vec<u8>,
) -> Result<(), String> {
    if iv.len() != cipher.block_size() {
        return Err(format!(
            "input vector is wrong length, expected {}, got {}",
            cipher.block_size(),
            iv.len()
        ));
    }
    if ciphertext.len() % cipher.block_size() != 0 {
        return Err(format!(
            "ciphertext length ({}) should be a multiple of the blocksize ({})",
            ciphertext.len(),
            cipher.block_size(),
        ));
    }

    let bs = cipher.block_size();
    let mut prev_block = iv.clone();

    for i in 0..(ciphertext.len() / bs) {
        let current_block = &mut ciphertext[(i * bs)..((i + 1) * bs)];

        // save the current ciphertext to remove
        // the chaining of the next block
        let pb = prev_block.clone();
        for i in 0..bs {
            prev_block[i] = current_block[i];
        }

        // decrypt current block
        cipher.decrypt_block(current_block);

        // Reverse the chaining
        for j in 0..cipher.block_size() {
            current_block[j] ^= pb[j];
        }
    }

    strip_padding(ciphertext);

    Ok(())
}

/// Any block cipher implementingthis trait may be used with the implementation of CBC with CTS.
pub trait BlockCipher {
    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);

    /// Block size for internal use
    fn block_size(&self) -> usize;

    /// The encryption mode, for internal use
    fn encryption_mode(&self) -> EncryptionMode {
        EncryptionMode::CBC
    }

    fn encrypt(&self, iv: &Vec<u8>, plaintext: &mut Vec<u8>) -> Result<(), String>
    where
        Self: std::marker::Sized,
    {
        use EncryptionMode::*;
        match self.encryption_mode() {
            CBC => cbc_encrypt(self, iv, plaintext),
        }
    }

    fn decrypt(&self, iv: &Vec<u8>, ciphertext: &mut Vec<u8>) -> Result<(), String>
    where
        Self: std::marker::Sized,
    {
        use EncryptionMode::*;
        match self.encryption_mode() {
            CBC => cbc_decrypt(self, iv, ciphertext),
        }
    }
}
