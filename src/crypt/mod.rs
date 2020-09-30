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
    let end_bytes = 32 >> 3;
    let zeros = bs - ((end_bytes + len as usize + 1) % bs);
    // append a one, a lot of zeros and then the number of padded bytes
    // ends up something like this:
    // 1 0 0 0 0 0 0 0 0 0 0 12
    bytes.append(
        &mut [1u8]
            .iter()
            .chain(
                std::iter::repeat(&0u8)
                    .take(zeros)
                    .chain(((zeros + end_bytes + 1) as u32).to_le_bytes().iter()),
            )
            .map(|x| *x)
            .collect(),
    );
}

fn strip_padding(bytes: &mut Vec<u8>) {
    let mut end = [0u8; 4];
    let offset = bytes.len() - std::mem::size_of::<u32>();

    for i in 0..4 {
        end[i] = bytes[i + offset];
    }

    let end = u32::from_le_bytes(end);
    let length = bytes.len();
    let end_range = || (length - end as usize)..length;

    for i in &mut bytes[end_range()] {
        *i = 0;
    }

    bytes.drain(end_range());
}

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
    let mut prev_block = Vec::new();
    for i in iv {
        prev_block.push(*i);
    }

    for i in 0..(ciphertext.len() / bs) {
        let curb = &ciphertext[(i * bs)..((i + 1) * bs)];
        let pb = prev_block.clone();
        for i in 0..bs {
            prev_block[i] = curb[i];
        }

        cipher.decrypt_block(&mut ciphertext[(i * bs)..((i + 1) * bs)]);
        for j in 0..cipher.block_size() {
            ciphertext[(i * bs) + j] ^= pb[j];
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
