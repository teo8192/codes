use num_bigint::{BigUint, ToBigUint};

use crate::number_theory::inverse;
use crate::prime::PrimeGenerator;

struct RSA {
    keys: (BigUint, BigUint),
    e: BigUint,
    d: BigUint,
    N: BigUint,
    size: usize,
}

impl RSA {
    pub fn new(size: usize) -> RSA {
        let s1 = size / 2 + 3;
        let s2 = size - s1;
        let mut rng = rand::thread_rng();
        let p1 = PrimeGenerator::rsa_prime(s1, &mut rng);
        let p2 = PrimeGenerator::rsa_prime(s2, &mut rng);


        let d = inverse(65535.to_biguint().unwrap(), (&p1 - 1.to_biguint().unwrap()) * (&p2 - 1.to_biguint().unwrap()));
        println!("{}, {}", p1, p2);
        let d = d.unwrap();

        let N = &p1 * &p2;

        RSA {
            keys: (p1, p2),
            e: 65535.to_biguint().unwrap(),
            d,
            N,
            size
        }
    }

    fn encrypt(&self, data: BigUint) -> BigUint {
        data.modpow(&self.e, &self.N)
    }

    fn decrypt(&self, data: BigUint) -> BigUint {
        data.modpow(&self.d, &self.N)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigUint, ToBigUint};
    #[test]
    fn create_keys() {
        let keys = RSA::new(1024);
        let encrypted = keys.encrypt(12345678.to_biguint().unwrap());
        assert_ne!(encrypted, 12345678.to_biguint().unwrap());
        let decrypted = keys.decrypt(encrypted);
        assert_eq!(decrypted, 12345678.to_biguint().unwrap());
    }
}
