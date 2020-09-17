use num_bigint::{BigUint, ToBigUint};

use crate::number_theory::inverse;
use crate::prime::PrimeGenerator;

struct RSA {
    keys: (BigUint, BigUint),
    e: BigUint,
    d: BigUint,
    pub n: BigUint,
    pub size: usize,
}

pub trait Crypt {
    fn encrypt(&mut self, bytes: Vec<u8>) -> Vec<BigUint>;
    fn decrypt(&mut self, nums: Vec<BigUint>) -> Vec<u8>;
    fn block_size(&self) -> usize;
}

impl RSA {
    pub fn new(size: usize) -> RSA {
        let s1 = size / 2 + 3;
        let s2 = size - s1;
        let mut rng = rand::thread_rng();
        let p1 = PrimeGenerator::rsa_prime(s1, &mut rng);
        let p2 = PrimeGenerator::rsa_prime(s2, &mut rng);

        let d = inverse(
            65535.to_biguint().unwrap(),
            (&p1 - 1.to_biguint().unwrap()) * (&p2 - 1.to_biguint().unwrap()),
        );
        let d = d.unwrap();

        let n = &p1 * &p2;

        // TODO: verify key length with log2

        RSA {
            keys: (p1, p2),
            e: 65535.to_biguint().unwrap(),
            d,
            n,
            size,
        }
    }

    fn encrypt_block(&self, data: &BigUint) -> BigUint {
        data.modpow(&self.e, &self.n)
    }

    fn decrypt_block(&self, data: &BigUint) -> BigUint {
        data.modpow(&self.d, &self.n)
    }
}

impl Crypt for RSA {
    fn encrypt(&mut self, bytes: Vec<u8>) -> Vec<BigUint> {
        let (mut rest, mut data) =
            bytes
                .iter()
                .fold((Vec::new(), Vec::new()), |(mut rest, mut data), byte| {
                    rest.push(*byte);
                    if (rest.len() + 1) * 8 >= self.block_size() {
                        data.push(self.encrypt_block(&BigUint::from_bytes_be(&mut rest.drain(0..(self.block_size() / 8)).collect::<Vec<u8>>()[..])));
                    }
                    (rest, data)
                });

        if rest.len() > 0 {
            data.push(self.encrypt_block(&BigUint::from_bytes_be(&mut rest.drain(0..rest.len()).collect::<Vec<u8>>()[..])));
        }

        data
    }

    fn decrypt(&mut self, nums: Vec<BigUint>) -> Vec<u8> {
        nums.iter().flat_map(|elem| self.decrypt_block(elem).to_bytes_be()).collect()
    }

    fn block_size(&self) -> usize {
        self.size - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigUint, ToBigUint};
    #[test]
    fn create_keys() {
        let num = 1234567890;
        let mut keys = RSA::new(512);
        let encrypted = keys.encrypt_block(&num.to_biguint().unwrap());
        assert_ne!(encrypted, num.to_biguint().unwrap());
        let decrypted = keys.decrypt_block(&encrypted);
        assert_eq!(decrypted, num.to_biguint().unwrap());

        // let string = b"hello motherfucker, hows life? is it good? i certanly hope so. if not, dont tell me".to_vec();
        let string = b"iuha diuh diuh seouihafhj sfjkhbsvcuyb serufy bwuyebf ysbad ufy busyrbef uyawb uefybakjshdbf askjnbvyu ba yuefb aywebf hkjbcvuybwae fb kwaebyf uyabweuof bwoeyf owyuevfbuoy vacd habs kfjhwuyefbgo uyagfouywe gffhbwefyb aygrf oygwehab fhbwcyb ygrfv aygwerfhjwbe fsjdbc uybsdovgh hbwoauebyf oyuasgdvyb h r yuagrrf87a9 7y 0ra7h bhhas hdbvuyhasbdv ygawbhfnmabsd,nmbasvcbhudcb oghr8 gar jh".to_vec();

        let encrypted = keys.encrypt(string.clone());

        assert!(encrypted.len() > 1);

        // println!("{:?}", encrypted);

        let decrypted = keys.decrypt(encrypted);

        use std::string::String;
        // println!("{:?}", decrypted);
        println!("{}", std::str::from_utf8(&decrypted[..]).expect("oh"));

        assert_eq!(decrypted, string);
    }
}
