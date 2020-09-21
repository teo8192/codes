/// The Advanced Encryption Standard, according to NIST FIPS 197
pub mod aes;

/// Naive textbook implementation of RSA.
pub mod rsa;

pub trait Crypt<'a, 'b, I: Iterator<Item = u8>, T, E: Iterator<Item=u8>, D: Iterator<Item=u8>> {
    fn encrypt(&'a mut self, crypt: &'b T) -> E;
    fn decrypt(&'a mut self, crypt: &'b T) -> D;
}
