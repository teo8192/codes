use crate::crypt::BlockCipher;

// {{{ constant substitution boxes.
// these should probably be removed, and replaced by a coputational alternative.
// This is to avoid timing attacks.  These timing attacks is possible since maybe
// only parts of the substitution box is used several times, and thus is in the cache. Then they
// would be faster to load again, and it is possible to guess when it is reused. I think, I am
// currently no expert on this kind of timing attack against AES.

const S_BOX: [u8; 256] = [
    0x63, 0xca, 0xb7, 0x04, 0x09, 0x53, 0xd0, 0x51, 0xcd, 0x60, 0xe0, 0xe7, 0xba, 0x70, 0xe1, 0x8c,
    0x7c, 0x82, 0xfd, 0xc7, 0x83, 0xd1, 0xef, 0xa3, 0x0c, 0x81, 0x32, 0xc8, 0x78, 0x3e, 0xf8, 0xa1,
    0x77, 0xc9, 0x93, 0x23, 0x2c, 0x00, 0xaa, 0x40, 0x13, 0x4f, 0x3a, 0x37, 0x25, 0xb5, 0x98, 0x89,
    0x7b, 0x7d, 0x26, 0xc3, 0x1a, 0xed, 0xfb, 0x8f, 0xec, 0xdc, 0x0a, 0x6d, 0x2e, 0x66, 0x11, 0x0d,
    0xf2, 0xfa, 0x36, 0x18, 0x1b, 0x20, 0x43, 0x92, 0x5f, 0x22, 0x49, 0x8d, 0x1c, 0x48, 0x69, 0xbf,
    0x6b, 0x59, 0x3f, 0x96, 0x6e, 0xfc, 0x4d, 0x9d, 0x97, 0x2a, 0x06, 0xd5, 0xa6, 0x03, 0xd9, 0xe6,
    0x6f, 0x47, 0xf7, 0x05, 0x5a, 0xb1, 0x33, 0x38, 0x44, 0x90, 0x24, 0x4e, 0xb4, 0xf6, 0x8e, 0x42,
    0xc5, 0xf0, 0xcc, 0x9a, 0xa0, 0x5b, 0x85, 0xf5, 0x17, 0x88, 0x5c, 0xa9, 0xc6, 0x0e, 0x94, 0x68,
    0x30, 0xad, 0x34, 0x07, 0x52, 0x6a, 0x45, 0xbc, 0xc4, 0x46, 0xc2, 0x6c, 0xe8, 0x61, 0x9b, 0x41,
    0x01, 0xd4, 0xa5, 0x12, 0x3b, 0xcb, 0xf9, 0xb6, 0xa7, 0xee, 0xd3, 0x56, 0xdd, 0x35, 0x1e, 0x99,
    0x67, 0xa2, 0xe5, 0x80, 0xd6, 0xbe, 0x02, 0xda, 0x7e, 0xb8, 0xac, 0xf4, 0x74, 0x57, 0x87, 0x2d,
    0x2b, 0xaf, 0xf1, 0xe2, 0xb3, 0x39, 0x7f, 0x21, 0x3d, 0x14, 0x62, 0xea, 0x1f, 0xb9, 0xe9, 0x0f,
    0xfe, 0x9c, 0x71, 0xeb, 0x29, 0x4a, 0x50, 0x10, 0x64, 0xde, 0x91, 0x65, 0x4b, 0x86, 0xce, 0xb0,
    0xd7, 0xa4, 0xd8, 0x27, 0xe3, 0x4c, 0x3c, 0xff, 0x5d, 0x5e, 0x95, 0x7a, 0xbd, 0xc1, 0x55, 0x54,
    0xab, 0x72, 0x31, 0xb2, 0x2f, 0x58, 0x9f, 0xf3, 0x19, 0x0b, 0xe4, 0xae, 0x8b, 0x1d, 0x28, 0xbb,
    0x76, 0xc0, 0x15, 0x75, 0x84, 0xcf, 0xa8, 0xd2, 0x73, 0xdb, 0x79, 0x08, 0x8a, 0x9e, 0xdf, 0x16,
];

const INV_S_BOX: [u8; 256] = [
    0x52, 0x7c, 0x54, 0x08, 0x72, 0x6c, 0x90, 0xd0, 0x3a, 0x96, 0x47, 0xfc, 0x1f, 0x60, 0xa0, 0x17,
    0x09, 0xe3, 0x7b, 0x2e, 0xf8, 0x70, 0xd8, 0x2c, 0x91, 0xac, 0xf1, 0x56, 0xdd, 0x51, 0xe0, 0x2b,
    0x6a, 0x39, 0x94, 0xa1, 0xf6, 0x48, 0xab, 0x1e, 0x11, 0x74, 0x1a, 0x3e, 0xa8, 0x7f, 0x3b, 0x04,
    0xd5, 0x82, 0x32, 0x66, 0x64, 0x50, 0x00, 0x8f, 0x41, 0x22, 0x71, 0x4b, 0x33, 0xa9, 0x4d, 0x7e,
    0x30, 0x9b, 0xa6, 0x28, 0x86, 0xfd, 0x8c, 0xca, 0x4f, 0xe7, 0x1d, 0xc6, 0x88, 0x19, 0xae, 0xba,
    0x36, 0x2f, 0xc2, 0xd9, 0x68, 0xed, 0xbc, 0x3f, 0x67, 0xad, 0x29, 0xd2, 0x07, 0xb5, 0x2a, 0x77,
    0xa5, 0xff, 0x23, 0x24, 0x98, 0xb9, 0xd3, 0x0f, 0xdc, 0x35, 0xc5, 0x79, 0xc7, 0x4a, 0xf5, 0xd6,
    0x38, 0x87, 0x3d, 0xb2, 0x16, 0xda, 0x0a, 0x02, 0xea, 0x85, 0x89, 0x20, 0x31, 0x0d, 0xb0, 0x26,
    0xbf, 0x34, 0xee, 0x76, 0xd4, 0x5e, 0xf7, 0xc1, 0x97, 0xe2, 0x6f, 0x9a, 0xb1, 0x2d, 0xc8, 0xe1,
    0x40, 0x8e, 0x4c, 0x5b, 0xa4, 0x15, 0xe4, 0xaf, 0xf2, 0xf9, 0xb7, 0xdb, 0x12, 0xe5, 0xeb, 0x69,
    0xa3, 0x43, 0x95, 0xa2, 0x5c, 0x46, 0x58, 0xbd, 0xcf, 0x37, 0x62, 0xc0, 0x10, 0x7a, 0xbb, 0x14,
    0x9e, 0x44, 0x0b, 0x49, 0xcc, 0x57, 0x05, 0x03, 0xce, 0xe8, 0x0e, 0xfe, 0x59, 0x9f, 0x3c, 0x63,
    0x81, 0xc4, 0x42, 0x6d, 0x5d, 0xa7, 0xb8, 0x01, 0xf0, 0x1c, 0xaa, 0x78, 0x27, 0x93, 0x83, 0x55,
    0xf3, 0xde, 0xfa, 0x8b, 0x65, 0x8d, 0xb3, 0x13, 0xb4, 0x75, 0x18, 0xcd, 0x80, 0xc9, 0x53, 0x21,
    0xd7, 0xe9, 0xc3, 0xd1, 0xb6, 0x9d, 0x45, 0x8a, 0xe6, 0xdf, 0xbe, 0x5a, 0xec, 0x9c, 0x99, 0x0c,
    0xfb, 0xcb, 0x4e, 0x25, 0x92, 0x84, 0x06, 0x6b, 0x73, 0x6e, 0x1b, 0xf4, 0x5f, 0xef, 0x61, 0x7d,
];

// }}}

#[derive(Clone)]
struct Block {
    data: Box<[u8; 16]>,
}

#[allow(dead_code)]
impl Block {
    /// Creates a new empty block, filled with zeros
    pub fn new() -> Self {
        Block {
            data: Box::new([0u8; 16]),
        }
    }

    /// Copy the content of another block into this block.
    pub fn copy(&mut self, other: &Block) {
        for i in 0..16 {
            self.data[i] = other.data[i];
        }
    }

    /// Transpose thoe block.
    /// The reason for this is that i do not want to rewrite the code.
    /// I think of the stuff row-major, but the peoples at NIST apparently think col-major.
    /// but a transpose will flip all this.
    /// So a transpose is needed before and after each encryption/decryption (no need from user,
    /// only internal use).
    fn transpose(&mut self) -> &mut Self {
        let mut out = [0u8; 16];
        for x in 0..4 {
            for y in 0..4 {
                out[x + y * 4] = self.data[y + x * 4];
            }
        }
        *self.data = out;

        self
    }

    /// Multiply two polynomials togeather over the finite field GF(2^8)
    /// this irreducible polynomial is x^8 + x^4 + x^3 + x + 1
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

        // multiply them shits
        // answer mught roll over, so use 16 bit.
        for i in 0..8 {
            res ^= a1 * (b1 & (1 << i));
        }

        // long division of the answer to get the remainder.
        // this will be at most 8 iterations.
        while log2(res) >= log2(modulus) {
            let shift = log2(res) - log2(modulus);
            assert!(shift <= 8);
            res ^= modulus << shift;
        }

        res as u8
    }

    /// Use S-box to substitute bytes.
    /// could be implementeted as the multiplicative inverse and
    /// a specific affine transformation
    fn sub_bytes(&mut self, inverse: bool) -> &mut Self {
        for i in 0..16 {
            let idx = (self.data[i] >> 4) | (self.data[i] << 4);
            self.data[i] = if inverse {
                INV_S_BOX[idx as usize]
            } else {
                S_BOX[idx as usize]
            };
        }

        self
    }

    /// Shift the rows.
    /// row n shifted n times, start from 0.
    /// inverse is just the other way.
    fn shift_rows(&mut self, inverse: bool) -> &mut Self {
        for i in 0..4 {
            let mut buf = [0u8; 4];
            for j in 0..4 {
                if inverse {
                    buf[j] = self.data[i * 4 + ((j + 4 - i) & 3)]
                } else {
                    buf[j] = self.data[i * 4 + ((i + j) & 3)];
                }
            }

            for j in 0..4 {
                self.data[j + i * 4] = buf[j];
            }
        }

        self
    }

    /// Hoenstly, this just mixes up the columns (but not across the different columns).
    fn mix_columns(&mut self, inverse: bool) -> &mut Self {
        let s = self.data.clone();
        let get_col_idx = |c, idx| s[c + idx as usize * 4];

        // this is a matrix where each row is shifted once from the row above
        let matrix = if inverse {
            [0xe, 0xb, 0xd, 0x9]
        } else {
            [2, 3, 1, 1]
        };
        for c in 0..4 {
            for i in 0..4 {
                let idx = 4 - i;
                self.data[c + i * 4] = Block::multiply_bytes(matrix[idx & 3], get_col_idx(c, 0))
                    ^ Block::multiply_bytes(matrix[(idx + 1) & 3], get_col_idx(c, 1))
                    ^ Block::multiply_bytes(matrix[(idx + 2) & 3], get_col_idx(c, 2))
                    ^ Block::multiply_bytes(matrix[(idx + 3) & 3], get_col_idx(c, 3));
            }
        }

        self
    }

    /// apply the 16 byte round key
    fn add_round_key(&mut self, w: &[u8]) -> &mut Self {
        for x in 0..4 {
            for y in 0..4 {
                self.data[x + y * 4] ^= w[x * 4 + y];
            }
        }

        self
    }
}

// {{{ Generic implementations for Block

impl std::iter::FromIterator<u8> for Block {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
        let mut bytes = Box::new([0u8; 16]);
        let mut i = 0;
        for b in iter {
            // i want to use enumberate, but I am not allowed (needs an Iterator, not IntoIterator)
            bytes[i] = b;
            i += 1;
        }
        Block { data: bytes }
    }
}

impl From<&[u8; 16]> for Block {
    fn from(bytes: &[u8; 16]) -> Self {
        Block {
            data: Box::new(*bytes),
        }
    }
}

impl From<Vec<u8>> for Block {
    fn from(bytes: Vec<u8>) -> Self {
        let mut data = Box::new([0u8; 16]);
        for i in 0..16 {
            data[i] = bytes[i];
        }

        Block { data }
    }
}

impl From<Block> for Vec<u8> {
    fn from(block: Block) -> Self {
        let mut new = Vec::with_capacity(16);
        for b in block.data.iter() {
            new.push(*b);
        }

        new
    }
}

impl From<&Block> for Vec<u8> {
    fn from(block: &Block) -> Self {
        let mut new = Vec::with_capacity(16);
        for b in block.data.iter() {
            new.push(*b);
        }

        new
    }
}

impl From<&mut Block> for Vec<u8> {
    fn from(block: &mut Block) -> Self {
        let mut new = Vec::with_capacity(16);
        for b in block.data.iter() {
            new.push(*b);
        }

        new
    }
}

impl std::fmt::Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for x in 0..4 {
            for y in 0..4 {
                write!(f, "{:02x}", self.data[x + y * 4])?;
            }
        }
        Ok(())
    }
}

// }}}

/// The specification of the key length
pub enum AESKey {
    AES128([u8; 16]),
    AES192([u8; 24]),
    AES256([u8; 32]),
}

/// The key AES key.
/// only contains the generated round key and number of rounds,
/// the rest (e.g. original key, number of rounds etc) seemed
/// to not be useful.
pub struct AES {
    w: Vec<u8>,
    nr: usize,
}

impl AES {
    /// Initialize the AES-thingy with the specified key.
    /// The key needs to be exactly the correct size,
    /// e.g. if you want 128, use exactly 16 bytes, 24 for 192, 32 for 256
    pub fn new(key_size: AESKey) -> AES {
        use AESKey::*;
        let (key, nr, nk) = match &key_size {
            AES128(key) => (&key[..], 10, 4),
            AES192(key) => (&key[..], 12, 6),
            AES256(key) => (&key[..], 14, 8),
        };

        // 16 = 4 * Nb
        let mut w = vec![0u8; 16 * (nr + 1)];
        AES::key_expansion(&key, &mut w, nk, nr);

        AES { w, nr }
    }

    /// this is from the [NIST FIPS 197, AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) paper.
    /// Look there for more details.
    fn key_expansion(key: &[u8], w: &mut Vec<u8>, nk: usize, nr: usize) {
        fn subword(a: &[u8; 4]) -> [u8; 4] {
            let mut bytes = [0u8; 4];
            for i in 0..4 {
                let idx = (a[i] >> 4) | (a[i] << 4);
                bytes[i] = S_BOX[idx as usize];
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
        for i in (nk as usize)..(4 * (nr + 1)) {
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
}

impl BlockCipher for AES {
    fn encrypt_block(&self, block: Vec<u8>) -> Vec<u8> {
        let mut input = Block::from(block);

        input.transpose().add_round_key(&self.w[0..16]);

        for round in 1..self.nr {
            input
                .sub_bytes(false)
                .shift_rows(false)
                .mix_columns(false)
                .add_round_key(&self.w[(round * 16)..((round + 1) * 16)]);
        }

        Vec::from(
            input
                .sub_bytes(false)
                .shift_rows(false)
                .add_round_key(&self.w[(self.nr * 16)..((self.nr + 1) * 16)])
                .transpose(),
        )
    }

    fn decrypt_block(&self, block: Vec<u8>) -> Vec<u8> {
        let mut input = Block::from(block);

        input
            .transpose()
            .add_round_key(&self.w[(self.nr * 16)..((self.nr + 1) * 16)]);

        for round in (1..self.nr).rev() {
            input
                .shift_rows(true)
                .sub_bytes(true)
                .add_round_key(&self.w[(round * 16)..((round + 1) * 16)])
                .mix_columns(true);
        }

        Vec::from(
            input
                .shift_rows(true)
                .sub_bytes(true)
                .add_round_key(&self.w[0..16])
                .transpose(),
        )
    }
    fn block_size(&self) -> usize {
        16
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiplication() {
        assert_eq!(Block::multiply_bytes(0x57, 0x83), 0xc1);
    }

    #[test]
    fn expand_key() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let mut w = vec![0u8; 240];
        AES::key_expansion(&key, &mut w, 8, 14);

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
    fn AES256() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];

        let aes = AES::new(AESKey::AES256(key));

        let content = b"hello motherfuck";

        let c = aes.encrypt_block(content.to_vec());
        println!("{:?}", c.to_vec());
        let d = aes.decrypt_block(c);
        println!("{:?}", d.to_vec());
        assert_eq!(d.to_vec(), content, "decryption faliure");
    }

    #[test]
    fn AES256ex() {
        let plaintext = [
            0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff,
        ];
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let aes = AES::new(AESKey::AES256(key));
        let c = aes.encrypt_block(plaintext.to_vec());
        println!("{:?}", c.to_vec());
        let output = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        assert_eq!(c.to_vec(), output, "encryption faliure");
        let d = aes.decrypt_block(c);
        println!("{:?}", d.to_vec());
        assert_eq!(d.to_vec(), plaintext, "decryption faliure");
    }

    #[test]
    fn AES128ex() {
        let plaintext = [
            0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff,
        ];
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let aes = AES::new(AESKey::AES128(key));
        let c = aes.encrypt_block(plaintext.to_vec());
        println!("{:?}", c.to_vec());
        let output = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        assert_eq!(c.to_vec(), output, "encryption faliure");
        let d = aes.decrypt_block(c);
        println!("{:?}", d.to_vec());
        assert_eq!(d.to_vec(), plaintext, "decryption faliure");
    }

    #[test]
    fn AES192ex() {
        let plaintext = [
            0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff,
        ];
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];

        let aes = AES::new(AESKey::AES192(key));
        let c = aes.encrypt_block(plaintext.to_vec());
        println!("{:?}", c.to_vec());
        let output = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
            0x71, 0x91,
        ];
        assert_eq!(c.to_vec(), output, "encryption faliure");
        let d = aes.decrypt_block(c);
        println!("{:?}", d.to_vec());
        assert_eq!(d.to_vec(), plaintext, "decryption faliure");
    }

    #[test]
    fn stream_test_iterator() {
        let plaintext = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. In pretium magna commodo, posuere lacus nec, tempor mi. Etiam vel cursus massa, in ornare arcu. Vivamus tortor metus, blandit vitae ultricies in, eleifend vitae magna. Pellentesque iaculis arcu leo, eu faucibus ex ultricies sed. Suspendisse velit velit, viverra sit amet leo vitae, porttitor egestas elit. Duis ut imperdiet lectus, ac iaculis ex. Maecenas venenatis nibh in erat malesuada, non aliquam nisi ultrices. Maecenas egestas mollis rhoncus. Vestibulum nunc leo, malesuada ac ornare sed, rutrum vitae mi. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos.

        Vestibulum sagittis ullamcorper odio, vel luctus justo dapibus lobortis. Aliquam finibus interdum massa, eget auctor urna lacinia vel. Suspendisse congue velit quis justo porttitor fringilla. Quisque vel aliquam nibh, ut congue metus. Nullam maximus, ipsum et efficitur ornare, justo mi malesuada ante, vitae accumsan est neque a ante. Ut cursus sed ex id elementum. Nulla purus massa, hendrerit quis porttitor et, volutpat id metus. Curabitur eget egestas nisl, vitae sodales diam. Donec a sapien eleifend, congue massa ut, aliquet lectus. Nunc in fermentum mauris, in dignissim dolor. Vestibulum tempor sed ipsum mattis lobortis. Proin in tellus at elit finibus tempus vitae sit amet mi. Ut ut bibendum dolor. Mauris nisl tortor, dignissim in metus eu, blandit venenatis odio.

        Fusce dapibus ac odio quis consectetur. Ut at lectus euismod sapien pretium eleifend. Praesent id massa non dolor pretium lacinia ut quis arcu. Vestibulum quis lorem ac odio tempor vestibulum ac at purus. Aenean dignissim enim ut iaculis accumsan. Suspendisse eget magna vitae magna euismod elementum ultricies nec quam. Sed malesuada sollicitudin lectus sed lobortis. Integer nec sapien vel arcu interdum accumsan. Phasellus finibus ut ex in sollicitudin. Fusce vestibulum pellentesque leo, efficitur tempor metus condimentum in. Aliquam a mauris ac augue lobortis accumsan vitae vel turpis. Nulla tempor eros velit, at aliquam dui fermentum vitae.

        In felis nisi, congue a mattis eget, aliquet nec neque. Quisque venenatis ante in arcu scelerisque euismod. Cras mollis, lacus a iaculis porttitor, lacus erat fermentum justo, non molestie enim neque et magna. Praesent non ornare ipsum, et feugiat eros. In porttitor dictum lobortis. Cras luctus urna vel justo consequat, non vestibulum dui placerat. Curabitur est nunc, lobortis sed vehicula vitae, ornare a urna. Sed bibendum aliquam rutrum. Pellentesque sodales tellus orci, et volutpat justo condimentum eget. Praesent magna sapien, porttitor a ante id, vehicula rutrum tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam suscipit lorem ac interdum varius. Sed varius metus eu dapibus hendrerit. Fusce consequat egestas varius.".to_vec();
        assert!(plaintext.len() & 15 != 0);

        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        use crate::crypt::Crypt;

        let aes = AES::new(AESKey::AES256(key));
        println!("{:?}", plaintext.len());
        let c: Vec<u8> = plaintext.clone().into_iter().encrypt(&aes).collect();
        println!("{:?}, {}", c, c.len());
        let d: Vec<u8> = c.clone().into_iter().decrypt(&aes).collect();
        println!("{:?}", d);
        assert_ne!(c, d);
        assert_eq!(d, plaintext, "decryption faliure");
        assert_eq!(c.len(), plaintext.len());

        println!("{}", plaintext.len());
    }
}
