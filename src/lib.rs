//! This is a test library for me to experement
//! both with Rust and with information theory.
//! The goal is to implement error detecting codes,
//! encryption and possibly compression.
//! Might also look at more shit on the way.

/// An implementation of AES block encryption, and cipher block chaining.
///
/// RSA is implemented, including key generation.
/// The keys have the property that phi(N) has no prime roots among the first 10^something
/// prime numbers.
pub mod crypt;

/// Simple codes for error detection and correction.
/// 11-5 hamming is implemented, corrects one bit in 16 bit block and detects two bit errors.
pub mod error;

/// Extended euclidian to find inverse etc.
pub mod number_theory;

/// Find primes.
/// Eratosthenes sieve and Rabin-Miller.
pub mod prime;
