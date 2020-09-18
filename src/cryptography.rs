use num_bigint::{BigUint, ToBigUint};

use crate::number_theory::inverse;
use crate::prime::PrimeGenerator;

struct RSA {
    // keys: (BigUint, BigUint),
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

fn print_box(b: &[u8; 16]) {
    for x in 0..4 {
        for y in 0..4 {
            print!("{:02x}", b[x + y * 4]);
        }
    }
    println!("");
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
            // keys: (p1, p2),
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
        // assert that the number of bytes is sufficient:
        // e^message > n
        // (2^16)^(message) > 2 ^ size
        // 16 * message > size
        // (2 ^ 4)*2(log2(bytes*8)) > size
        // 4 + log2(bytes*8) > log2(size)
        // 7 + log2(bytes) > log2(size)
        // log2(bytes) > log2(size) - 7
        // log2(bytes) > log2(size >> 7)
        // bytes) > size >> 7

        // TODO: instead of asserting, pad shit
        assert!(bytes.len() > self.size >> 7);
        let (mut rest, mut data) =
            bytes
                .iter()
                .fold((Vec::new(), Vec::new()), |(mut rest, mut data), byte| {
                    rest.push(*byte);
                    if (rest.len() + 1) * 8 >= self.block_size() {
                        data.push(self.encrypt_block(&BigUint::from_bytes_be(
                            &mut rest.drain(0..(self.block_size() / 8)).collect::<Vec<u8>>()[..],
                        )));
                    }
                    (rest, data)
                });

        assert!(rest.len() > self.size >> 7);

        if rest.len() > 0 {
            data.push(self.encrypt_block(&BigUint::from_bytes_be(
                &mut rest.drain(0..rest.len()).collect::<Vec<u8>>()[..],
            )));
        }

        data
    }

    fn decrypt(&mut self, nums: Vec<BigUint>) -> Vec<u8> {
        nums.iter()
            .flat_map(|elem| self.decrypt_block(elem).to_bytes_be())
            .collect()
    }

    fn block_size(&self) -> usize {
        self.size - 1
    }
}

fn transpose(input: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for x in 0..4 {
        for y in 0..4 {
            out[x + y * 4] = input[y + x * 4];
        }
    }

    out
}

struct AES256 {
    key: [u8; 32],
}

impl AES256 {
    const number_rounds: usize = 14;

    fn cipher(input: &[u8; 16], w: &[u8; 16 * (AES256::number_rounds + 1)]) -> [u8; 16] {
        let mut state = transpose(&input);
        use std::convert::TryInto;

        AES256::add_round_key(&mut state, &w[0..(4 * 4)].try_into().expect("Wrong length"));

        for round in 1..AES256::number_rounds {
            AES256::sub_bytes(&mut state, false);
            AES256::shift_rows(&mut state, false);
            AES256::mix_columns(&mut state, false);
            AES256::add_round_key(
                &mut state,
                &w[(round * 16)..((round + 1) * 16)]
                    .try_into()
                    .expect("Wrong length"),
            );
        }

        AES256::sub_bytes(&mut state, false);
        AES256::shift_rows(&mut state, false);
        AES256::add_round_key(
            &mut state,
            &w[(AES256::number_rounds * 16)..((AES256::number_rounds + 1) * 16)]
                .try_into()
                .expect("Wrong length"),
        );

        transpose(&state)
    }

    fn change_byte(byte: u8, inverse: bool) -> u8 {
        // TODO: do mathematically?
        // fn inverse_byte(byte: u8) -> u8 {
        //     0
        // }
        // let bit = |byte: u8, pos: u32| (byte >> (pos & 7)) & 1;
        // let inverse = |b: u8, i: u32| {
        //     bit(b, i) ^ bit(b, i + 4) ^ bit(b, i + 5) ^ bit(b, i + 6) ^ bit(b, i + 7) ^ bit(0x63u8, i)
        // };

        // let mut b = 0;
        // let inv = AES256::inverse_byte(byte);
        // for i in 0..8 {
        //     b |= inverse(inv, i) << i;
        // }
        // b
        let idx = (byte >> 4) | (byte << 4);
        let table = [
            0x63, 0xca, 0xb7, 0x04, 0x09, 0x53, 0xd0, 0x51, 0xcd, 0x60, 0xe0, 0xe7, 0xba, 0x70,
            0xe1, 0x8c, 0x7c, 0x82, 0xfd, 0xc7, 0x83, 0xd1, 0xef, 0xa3, 0x0c, 0x81, 0x32, 0xc8,
            0x78, 0x3e, 0xf8, 0xa1, 0x77, 0xc9, 0x93, 0x23, 0x2c, 0x00, 0xaa, 0x40, 0x13, 0x4f,
            0x3a, 0x37, 0x25, 0xb5, 0x98, 0x89, 0x7b, 0x7d, 0x26, 0xc3, 0x1a, 0xed, 0xfb, 0x8f,
            0xec, 0xdc, 0x0a, 0x6d, 0x2e, 0x66, 0x11, 0x0d, 0xf2, 0xfa, 0x36, 0x18, 0x1b, 0x20,
            0x43, 0x92, 0x5f, 0x22, 0x49, 0x8d, 0x1c, 0x48, 0x69, 0xbf, 0x6b, 0x59, 0x3f, 0x96,
            0x6e, 0xfc, 0x4d, 0x9d, 0x97, 0x2a, 0x06, 0xd5, 0xa6, 0x03, 0xd9, 0xe6, 0x6f, 0x47,
            0xf7, 0x05, 0x5a, 0xb1, 0x33, 0x38, 0x44, 0x90, 0x24, 0x4e, 0xb4, 0xf6, 0x8e, 0x42,
            0xc5, 0xf0, 0xcc, 0x9a, 0xa0, 0x5b, 0x85, 0xf5, 0x17, 0x88, 0x5c, 0xa9, 0xc6, 0x0e,
            0x94, 0x68, 0x30, 0xad, 0x34, 0x07, 0x52, 0x6a, 0x45, 0xbc, 0xc4, 0x46, 0xc2, 0x6c,
            0xe8, 0x61, 0x9b, 0x41, 0x01, 0xd4, 0xa5, 0x12, 0x3b, 0xcb, 0xf9, 0xb6, 0xa7, 0xee,
            0xd3, 0x56, 0xdd, 0x35, 0x1e, 0x99, 0x67, 0xa2, 0xe5, 0x80, 0xd6, 0xbe, 0x02, 0xda,
            0x7e, 0xb8, 0xac, 0xf4, 0x74, 0x57, 0x87, 0x2d, 0x2b, 0xaf, 0xf1, 0xe2, 0xb3, 0x39,
            0x7f, 0x21, 0x3d, 0x14, 0x62, 0xea, 0x1f, 0xb9, 0xe9, 0x0f, 0xfe, 0x9c, 0x71, 0xeb,
            0x29, 0x4a, 0x50, 0x10, 0x64, 0xde, 0x91, 0x65, 0x4b, 0x86, 0xce, 0xb0, 0xd7, 0xa4,
            0xd8, 0x27, 0xe3, 0x4c, 0x3c, 0xff, 0x5d, 0x5e, 0x95, 0x7a, 0xbd, 0xc1, 0x55, 0x54,
            0xab, 0x72, 0x31, 0xb2, 0x2f, 0x58, 0x9f, 0xf3, 0x19, 0x0b, 0xe4, 0xae, 0x8b, 0x1d,
            0x28, 0xbb, 0x76, 0xc0, 0x15, 0x75, 0x84, 0xcf, 0xa8, 0xd2, 0x73, 0xdb, 0x79, 0x08,
            0x8a, 0x9e, 0xdf, 0x16,
        ];

        let inv_table = [
            0x52, 0x7c, 0x54, 0x08, 0x72, 0x6c, 0x90, 0xd0, 0x3a, 0x96, 0x47, 0xfc, 0x1f, 0x60,
            0xa0, 0x17, 0x09, 0xe3, 0x7b, 0x2e, 0xf8, 0x70, 0xd8, 0x2c, 0x91, 0xac, 0xf1, 0x56,
            0xdd, 0x51, 0xe0, 0x2b, 0x6a, 0x39, 0x94, 0xa1, 0xf6, 0x48, 0xab, 0x1e, 0x11, 0x74,
            0x1a, 0x3e, 0xa8, 0x7f, 0x3b, 0x04, 0xd5, 0x82, 0x32, 0x66, 0x64, 0x50, 0x00, 0x8f,
            0x41, 0x22, 0x71, 0x4b, 0x33, 0xa9, 0x4d, 0x7e, 0x30, 0x9b, 0xa6, 0x28, 0x86, 0xfd,
            0x8c, 0xca, 0x4f, 0xe7, 0x1d, 0xc6, 0x88, 0x19, 0xae, 0xba, 0x36, 0x2f, 0xc2, 0xd9,
            0x68, 0xed, 0xbc, 0x3f, 0x67, 0xad, 0x29, 0xd2, 0x07, 0xb5, 0x2a, 0x77, 0xa5, 0xff,
            0x23, 0x24, 0x98, 0xb9, 0xd3, 0x0f, 0xdc, 0x35, 0xc5, 0x79, 0xc7, 0x4a, 0xf5, 0xd6,
            0x38, 0x87, 0x3d, 0xb2, 0x16, 0xda, 0x0a, 0x02, 0xea, 0x85, 0x89, 0x20, 0x31, 0x0d,
            0xb0, 0x26, 0xbf, 0x34, 0xee, 0x76, 0xd4, 0x5e, 0xf7, 0xc1, 0x97, 0xe2, 0x6f, 0x9a,
            0xb1, 0x2d, 0xc8, 0xe1, 0x40, 0x8e, 0x4c, 0x5b, 0xa4, 0x15, 0xe4, 0xaf, 0xf2, 0xf9,
            0xb7, 0xdb, 0x12, 0xe5, 0xeb, 0x69, 0xa3, 0x43, 0x95, 0xa2, 0x5c, 0x46, 0x58, 0xbd,
            0xcf, 0x37, 0x62, 0xc0, 0x10, 0x7a, 0xbb, 0x14, 0x9e, 0x44, 0x0b, 0x49, 0xcc, 0x57,
            0x05, 0x03, 0xce, 0xe8, 0x0e, 0xfe, 0x59, 0x9f, 0x3c, 0x63, 0x81, 0xc4, 0x42, 0x6d,
            0x5d, 0xa7, 0xb8, 0x01, 0xf0, 0x1c, 0xaa, 0x78, 0x27, 0x93, 0x83, 0x55, 0xf3, 0xde,
            0xfa, 0x8b, 0x65, 0x8d, 0xb3, 0x13, 0xb4, 0x75, 0x18, 0xcd, 0x80, 0xc9, 0x53, 0x21,
            0xd7, 0xe9, 0xc3, 0xd1, 0xb6, 0x9d, 0x45, 0x8a, 0xe6, 0xdf, 0xbe, 0x5a, 0xec, 0x9c,
            0x99, 0x0c, 0xfb, 0xcb, 0x4e, 0x25, 0x92, 0x84, 0x06, 0x6b, 0x73, 0x6e, 0x1b, 0xf4,
            0x5f, 0xef, 0x61, 0x7d,
        ];

        if inverse {
            inv_table[idx as usize]
        } else {
            table[idx as usize]
        }
    }

    fn multiply_bytes(a: u8, b: u8) -> u8 {
        fn log2(mut a: u16) -> u16 {
            let mut res = 0;
            while a > 1 {
                a >>= 1;
                res += 1;
            }

            res
        }

        let modulus = 0x011b;
        let mut res: u16 = 0;
        let a1 = a as u16;
        let b1 = b as u16;
        for i in 0..8 {
            res ^= a1 * (b1 & (1 << i));
        }

        while log2(res) >= log2(modulus) {
            let shift = log2(res) - log2(modulus);
            assert!(shift >= 0);
            assert!(shift <= 8);
            res ^= modulus << shift;
        }

        res as u8
    }

    fn sub_bytes(state: &mut [u8; 16], inverse: bool) {
        for i in 0..16 {
            state[i] = AES256::change_byte(state[i], inverse);
        }
    }

    fn shift_rows(state: &mut [u8; 16], inverse: bool) {
        for i in 0..4 {
            let mut buf = [0u8; 4];
            for j in 0..4 {
                if inverse {
                    buf[j] = state[i * 4 + ((j + 4 - i) & 3)]
                } else {
                    buf[j] = state[i * 4 + ((i + j) & 3)];
                }
            }

            for j in 0..4 {
                state[j + i * 4] = buf[j];
            }
        }
    }

    fn mix_columns(state: &mut [u8; 16], inverse: bool) {
        let s = state.clone();
        let get_col_idx = |c, idx| s[c + idx as usize * 4];
        let mut col = [0u8; 4];
        for c in 0..4 {
            if inverse {
                col[0] = AES256::multiply_bytes(0xe, get_col_idx(c, 0))
                    ^ AES256::multiply_bytes(0xb, get_col_idx(c, 1))
                    ^ AES256::multiply_bytes(0xd, get_col_idx(c, 2))
                    ^ AES256::multiply_bytes(0x9, get_col_idx(c, 3));

                col[1] = AES256::multiply_bytes(0x9, get_col_idx(c, 0))
                    ^ AES256::multiply_bytes(0xe, get_col_idx(c, 1))
                    ^ AES256::multiply_bytes(0xb, get_col_idx(c, 2))
                    ^ AES256::multiply_bytes(0xd, get_col_idx(c, 3));

                col[2] = AES256::multiply_bytes(0xd, get_col_idx(c, 0))
                    ^ AES256::multiply_bytes(0x9, get_col_idx(c, 1))
                    ^ AES256::multiply_bytes(0xe, get_col_idx(c, 2))
                    ^ AES256::multiply_bytes(0xb, get_col_idx(c, 3));

                col[3] = AES256::multiply_bytes(0xb, get_col_idx(c, 0))
                    ^ AES256::multiply_bytes(0xd, get_col_idx(c, 1))
                    ^ AES256::multiply_bytes(0x9, get_col_idx(c, 2))
                    ^ AES256::multiply_bytes(0xe, get_col_idx(c, 3));
            } else {
                col[0] = AES256::multiply_bytes(2, get_col_idx(c, 0))
                    ^ AES256::multiply_bytes(3, get_col_idx(c, 1))
                    ^ get_col_idx(c, 2)
                    ^ get_col_idx(c, 3);

                col[1] = get_col_idx(c, 0)
                    ^ AES256::multiply_bytes(2, get_col_idx(c, 1))
                    ^ AES256::multiply_bytes(3, get_col_idx(c, 2))
                    ^ get_col_idx(c, 3);

                col[2] = get_col_idx(c, 0)
                    ^ get_col_idx(c, 1)
                    ^ AES256::multiply_bytes(2, get_col_idx(c, 2))
                    ^ AES256::multiply_bytes(3, get_col_idx(c, 3));

                col[3] = AES256::multiply_bytes(3, get_col_idx(c, 0))
                    ^ get_col_idx(c, 1)
                    ^ get_col_idx(c, 2)
                    ^ AES256::multiply_bytes(2, get_col_idx(c, 3));
            }

            for i in 0..4 {
                state[c + i * 4] = col[i];
            }
        }
    }

    fn add_round_key(state: &mut [u8; 16], w: &[u8; 16]) {
        let mut tmp = [0u8; 16];
        for x in 0..4 {
            for y in 0..4 {
                tmp[x + y * 4] = state[x + y * 4] ^ w[x * 4 + y];
            }
        }
        for i in 0..16 {
            state[i] = tmp[i];
        }
    }

    fn key_expansion(key: &[u8; 32], w: &mut [u8; 16 * (AES256::number_rounds + 1)], nk: usize) {
        fn subword(a: &[u8; 4]) -> [u8; 4] {
            let mut bytes = [0u8; 4];
            for i in 0..4 {
                bytes[i] = AES256::change_byte(a[i], false);
            }

            bytes
        }

        fn rotword(a: &[u8; 4]) -> [u8; 4] {
            let mut bytes = [0u8; 4];
            for i in 0..4 {
                bytes[i] = a[(i + 1) & 3];
            }

            bytes
        }

        fn next_rc(rc: u8) -> u8 {
            if rc < 0x80 {
                rc << 1
            } else {
                (((rc as u16) << 1) ^ 0x11b) as u8
            }
        }
        let mut rcon = [0u8; 4];

        let mut tmp = [0u8; 4];

        for i in 0..nk {
            for j in 0..4 {
                w[i * 4 + j] = key[i * 4 + j];
            }
        }

        let mut rc = 1;
        for i in (nk as usize)..(4 * (AES256::number_rounds + 1)) {
            for j in 0..4 {
                tmp[j as usize] = w[((i - 1) * 4 + j) as usize];
            }

            if i % nk == 0 {
                rcon[0] = rc;
                tmp = subword(&rotword(&tmp));
                for j in 0..4 {
                    tmp[j] ^= rcon[j];
                }
                rc = next_rc(rc);
            } else if nk > 6 && i % nk == 4 {
                tmp = subword(&tmp);
            }
            for j in 0..4 {
                w[i * 4 + j] = w[(i - nk) * 4 + j] ^ tmp[j];
            }
        }
    }

    fn inv_cipher(input: &[u8; 16], w: &[u8; 16 * (AES256::number_rounds + 1)]) -> [u8; 16] {
        let mut state = transpose(&input);
        use std::convert::TryInto;

        AES256::add_round_key(
            &mut state,
            &w[(AES256::number_rounds * 16)..((AES256::number_rounds + 1) * 16)]
                .try_into()
                .expect("Wrong length"),
        );

        for round in (1..AES256::number_rounds).rev() {
            AES256::shift_rows(&mut state, true);
            AES256::sub_bytes(&mut state, true);
            AES256::add_round_key(
                &mut state,
                &w[(round * 16)..((round + 1) * 16)]
                    .try_into()
                    .expect("Wrong length"),
            );
            AES256::mix_columns(&mut state, true);
        }

        AES256::shift_rows(&mut state, true);
        AES256::sub_bytes(&mut state, true);
        AES256::add_round_key(&mut state, &w[0..16].try_into().expect("Wrong length"));

        transpose(&state)
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
        let string = b"iuha diuh diuh seouihafhj sfjkhbsvcuyb serufy bwuyebf ysbad ufy busyrbef uyawb uefybakjshdbf askjnbvyu ba yuefb aywebf hkjbcvuybwae fb kwaebyf uyabweuof bwoeyf owyuevfbuoy vacd habs kfjhwuyefbgo uyagfouywe gffhbwefyb aygrf oygwehab fhbwcyb ygrfv aygwerfhjwbe fsjdbc uybsdovgh hbwoauebyf oyuasgdvyb h r yuagrrf87a9 7y 0ra7h bhhas hdbvuyhasbdv ygawbhfnmabsd,nmbasvcbhudcb oghr8 gar jhioj".to_vec();
        // let string = b"awdoiawjd".to_vec();

        let encrypted = keys.encrypt(string.clone());

        assert!(encrypted.len() > 1);

        // println!("{:?}", encrypted);

        let decrypted = keys.decrypt(encrypted);

        use std::string::String;
        // println!("{:?}", decrypted);
        println!("{}", std::str::from_utf8(&decrypted[..]).expect("oh"));

        assert_eq!(decrypted, string);
    }

    fn big(x: u32) -> BigUint {
        x.to_biguint().unwrap()
    }

    #[test]
    fn test_byte_change() {
        assert_eq!(AES256::change_byte(0xe0, false), 0xe1);
        assert_eq!(AES256::change_byte(0x0e, false), 0xab);
        assert_eq!(AES256::change_byte(0xfa, false), 0x2d);
        assert_eq!(AES256::change_byte(0x7c, false), 0x10);
        assert_eq!(AES256::change_byte(0x00, false), 0x63);
        assert_eq!(AES256::change_byte(0xff, false), 0x16);

        assert_eq!(AES256::change_byte(0xe0, true), 0xa0);
        assert_eq!(AES256::change_byte(0x0e, true), 0xd7);
        assert_eq!(AES256::change_byte(0xfa, true), 0x14);
        assert_eq!(AES256::change_byte(0x7c, true), 0x01);
        assert_eq!(AES256::change_byte(0x00, true), 0x52);
        assert_eq!(AES256::change_byte(0xff, true), 0x7d);

        for i in 0..=255 {
            assert_eq!(AES256::change_byte(AES256::change_byte(i, false), true), i);
        }
    }

    #[test]
    fn test_multiplication() {
        assert_eq!(AES256::multiply_bytes(0x57, 0x83), 0xc1);
    }

    #[test]
    fn expand_key() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let mut w = [0u8; 240];
        AES256::key_expansion(&key, &mut w, 8);

        let expected = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4, 0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a,
            0x8b, 0x5f, 0x20, 0x67, 0xfc, 0xde, 0xa8, 0xb0, 0x9c, 0x1a, 0x93, 0xd1, 0x94, 0xcd,
            0xbe, 0x49, 0x84, 0x6e, 0xb7, 0x5d, 0x5b, 0x9a, 0xd5, 0x9a, 0xec, 0xb8, 0x5b, 0xf3,
            0xc9, 0x17,
        ];

        for (i, b) in expected.iter().enumerate() {
            assert_eq!(*b, w[i], "key expansion failiure, {}", i);
        }
    }

    #[test]
    fn aes256() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];

        let mut w = [0u8; 240];
        AES256::key_expansion(&key, &mut w, 8);

        let content = b"hello motherfuck";

        let c = AES256::cipher(&content, &w);
        println!("{:?}", c);
        let d = AES256::inv_cipher(&c, &w);
        println!("{:?}", d);
        assert_eq!(&d, content, "decryption faliure");
    }

    #[test]
    fn aes256ex() {
        let plaintext = [
            0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff,
        ];
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let mut w = [0u8; 240];
        AES256::key_expansion(&key, &mut w, 8);

        let c = AES256::cipher(&plaintext, &w);
        println!("{:?}", c);
        let output = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        assert_eq!(c, output, "encryption faliure");
        let d = AES256::inv_cipher(&c, &w);
        println!("{:?}", d);
        assert_eq!(d, plaintext, "decryption faliure");
    }
}
