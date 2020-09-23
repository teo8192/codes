/// The Advanced Encryption Standard, according to NIST FIPS 197
pub mod aes;
pub use aes::{AESKeySize, AES};

/// Naive textbook implementation of RSA.
pub mod rsa;

pub trait Crypt<'a, 'b, C, I, E: Iterator<Item = I>, D: Iterator<Item = I>>:
    Iterator<Item = I>
{
    fn encrypt(&'a mut self, crypt: &'b C) -> E;
    fn decrypt(&'a mut self, crypt: &'b C) -> D;
}
