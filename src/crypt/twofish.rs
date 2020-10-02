use super::BlockCipher;

macro_rules! sum {
    ($elem1:expr, $elem2:expr, $( $rest:expr ),+ ) => {{
        sum!($elem1.overflowing_add($elem2).0, $( $rest ),+)
    }};
    ($elem1:expr, $elem2:expr) => {{
        sum!($elem1.overflowing_add($elem2).0)
    }};
    ($x:expr) => {{$x}};
    () => {{}};
}

macro_rules! rotl {
    ($x:expr, $n:expr) => {{
        $x.rotate_left($n)
    }};
}

macro_rules! ror41 {
    ($x:expr) => {{
        (($x & 1) << 3) | ($x >> 1)
    }};
}

struct Twofish {
    s: Vec<u32>,
    k: Box<[u32; 40]>,
}

impl Twofish {
    pub fn new(key: &[u8]) -> Twofish {
        let (k, s) = expand_key(key);
        Twofish { s, k }
    }

    fn g(&self, input: u32) -> u32 {
        h(input, &self.s)
    }

    fn f(&self, r_0: u32, r_1: u32, r: usize) -> (u32, u32) {
        let t_0 = self.g(r_0);
        let t_1 = self.g(rotl!(r_1, 8));

        (
            sum!(t_0, t_1, self.k[2 * r + 8]),
            sum!(t_0, t_1.overflowing_shl(1).0, self.k[2 * r + 9]),
        )
    }
}

impl BlockCipher for Twofish {
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut input = convert_to_block(block);

        for (n, b) in input.iter_mut().enumerate() {
            *b ^= self.k[n];
        }

        for r in 0..16 {
            let (f0, f1) = self.f(input[0], input[1], r);

            let r0 = (input[2] ^ f0).rotate_right(1);
            let r1 = input[3].rotate_left(1) ^ f1;
            let r2 = input[0];
            let r3 = input[1];

            input[0] = r0;
            input[1] = r1;
            input[2] = r2;
            input[3] = r3;
        }

        let mut c = [0u32; 4];

        for i in 0..4 {
            c[i] = input[(i + 2) & 3] ^ self.k[i + 4];
        }

        for (n, b) in input.iter_mut().enumerate() {
            *b = c[n];
        }

        let o = convert_from_block(input);
        for (block, out) in block.iter_mut().zip(o.iter()) {
            *block = *out;
        }
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        let mut input = convert_to_block(block);

        let mut c = [0u32; 4];

        for (n, b) in input.iter().enumerate() {
            c[(n + 2) & 3] = *b ^ self.k[n + 4];
        }

        for (n, b) in input.iter_mut().enumerate() {
            *b = c[n];
        }

        for r in (0..16).rev() {
            let (f0, f1) = self.f(input[2], input[3], r);

            let r2 = input[0].rotate_left(1) ^ f0;
            let r3 = (input[1] ^ f1).rotate_right(1);
            let r0 = input[2];
            let r1 = input[3];

            input[0] = r0;
            input[1] = r1;
            input[2] = r2;
            input[3] = r3;
        }

        for (n, b) in input.iter_mut().enumerate() {
            *b ^= self.k[n];
        }

        let o = convert_from_block(input);
        for (block, out) in block.iter_mut().zip(o.iter()) {
            *block = *out;
        }
    }

    fn block_size(&self) -> usize {
        16
    }

    fn change_encryption_mode(&mut self, mode: super::EncryptionMode) -> &mut Self {
        self
    }
}

fn convert_to_block(block: &[u8]) -> Box<[u32; 4]> {
    let mut p = [0; 4];

    for i in 0..4 {
        let mut conv_arr = [0u8; 4];
        for (n, b) in conv_arr.iter_mut().enumerate() {
            *b = block[(i << 2) + n];
        }
        p[i] = u32::from_le_bytes(conv_arr);
    }
    Box::new(p)
}

fn convert_from_block(block: Box<[u32; 4]>) -> Box<[u8; 16]> {
    let mut res = [0u8; 16];

    for i in 0..4 {
        let tmp = u32::to_le_bytes(block[i]);
        for j in 0..4 {
            res[(i << 2) + j] = tmp[j];
        }
    }

    Box::new(res)
}

const MDS: [u8; 16] = [
    0x01, 0xef, 0x5b, 0x5b, 0x5b, 0xef, 0xef, 0x01, 0xef, 0x5b, 0x01, 0xef, 0xef, 0x01, 0xef, 0x5b,
];

fn multiply_bytes(a: u8, b: u8, modulus: u16) -> u8 {
    fn log2(mut a: u16) -> u16 {
        let mut res = 0;
        while a > 1 {
            a >>= 1;
            res += 1;
        }

        res
    }

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

const RS: [u8; 32] = [
    0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5,
    0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03,
];

fn mulrs(input: [u8; 8]) -> u32 {
    let mut res = [0u8; 4];

    // Should be multiplication over GF(2^8) modulo w(x)=x^8+x^6+x^3+x^2+1 (0b101001101=0x14d)
    for i in 0..4 {
        for j in 0..8 {
            res[i] ^= multiply_bytes(input[j], RS[(i << 3) + j], 0x14d);
        }
    }

    u32::from_le_bytes(res)
}

macro_rules! qperm {
    ($x:expr, $t0:expr, $t1:expr, $t2:expr, $t3:expr) => {{
        // split into nibbles
        let a_0 = $x >> 4;
        let b_0 = $x & 0xf;

        let a_1 = a_0 ^ b_0;
        let b_1 = a_0 ^ ror41!(b_0) ^ ((a_0 << 3) & 0xf);

        let a_2 = $t0[a_1 as usize];
        let b_2 = $t1[b_1 as usize];

        let a_3 = a_2 ^ b_2;
        let b_3 = a_2 ^ ror41!(b_2) ^ ((a_2 << 3) & 0xf);

        let a_4 = $t2[a_3 as usize];
        let b_4 = $t3[b_3 as usize];

        (b_4 << 4) | a_4
    }};
}

fn q0(x: u8) -> u8 {
    qperm!(
        x,
        [0x8, 0x1, 0x7, 0xd, 0x6, 0xf, 0x3, 0x2, 0x0, 0xb, 0x5, 0x9, 0xe, 0xc, 0xa, 0x4],
        [0xe, 0xc, 0xb, 0x8, 0x1, 0x2, 0x3, 0x5, 0xf, 0x4, 0xa, 0x6, 0x7, 0x0, 0x9, 0xd],
        [0xb, 0xa, 0x5, 0xe, 0x6, 0xd, 0x9, 0x0, 0xc, 0x8, 0xf, 0x3, 0x2, 0x4, 0x7, 0x1],
        [0xd, 0x7, 0xf, 0x4, 0x1, 0x2, 0x6, 0xe, 0x9, 0xb, 0x3, 0x0, 0x8, 0x5, 0xc, 0xa]
    )
}

fn q1(x: u8) -> u8 {
    qperm!(
        x,
        [0x2, 0x8, 0xb, 0xd, 0xf, 0x7, 0x6, 0xe, 0x3, 0x1, 0x9, 0x4, 0x0, 0xa, 0xc, 0x5],
        [0x1, 0xe, 0x2, 0xb, 0x4, 0xc, 0x3, 0x7, 0x6, 0xd, 0xa, 0x5, 0xf, 0x9, 0x0, 0x8],
        [0x4, 0xc, 0x7, 0x5, 0x1, 0x6, 0x9, 0xa, 0x0, 0xe, 0xd, 0x8, 0x2, 0xb, 0x3, 0xf],
        [0xb, 0x9, 0x5, 0x1, 0xc, 0x3, 0xd, 0xe, 0x6, 0x4, 0x7, 0xf, 0x2, 0x0, 0x8, 0xa]
    )
}

fn h(X: u32, L: &Vec<u32>) -> u32 {
    let k = L.len();
    let x = X.to_le_bytes();

    let y = {
        let mut inner = (x[0], x[1], x[2], x[3]);
        if k == 4 {
            let l = L[3].to_le_bytes();
            inner = (
                q1(inner.0) ^ l[0],
                q0(inner.1) ^ l[1],
                q0(inner.2) ^ l[2],
                q1(inner.3) ^ l[3],
            );
        }
        if k >= 3 {
            let l = L[2].to_le_bytes();
            inner = (
                q1(inner.0) ^ l[0],
                q1(inner.1) ^ l[1],
                q0(inner.2) ^ l[2],
                q0(inner.3) ^ l[3],
            );
        }
        let l = L[1].to_le_bytes();
        inner = (
            q0(inner.0) ^ l[0],
            q1(inner.1) ^ l[1],
            q0(inner.2) ^ l[2],
            q1(inner.3) ^ l[3],
        );

        let l = L[0].to_le_bytes();
        inner = (
            q0(inner.0) ^ l[0],
            q0(inner.1) ^ l[1],
            q1(inner.2) ^ l[2],
            q1(inner.3) ^ l[3],
        );

        [q1(inner.0), q0(inner.1), q1(inner.2), q0(inner.3)]
    };

    let mut res = [0u8; 4];

    for i in 0..4 {
        for j in 0..4 {
            // Over GF(2^8) with polynomial x^8+x^6+x^5+x^3+1 <=> 0b101101001 = 0x169
            res[i] ^= multiply_bytes(y[j], MDS[(i << 2) + j], 0x169);
        }
    }

    u32::from_le_bytes(res)
}

fn expand_key(key: &[u8]) -> (Box<[u32; 40]>, Vec<u32>) {
    let k = key.len() >> 3; // N / 64
    let mut m_e: Vec<u32> = Vec::new();
    let mut m_o: Vec<u32> = Vec::new();
    let mut s: Vec<u32> = Vec::new();
    for i in 0..(k << 1) {
        let mut pos = [0u8; 4];
        for (n, b) in pos.iter_mut().enumerate() {
            *b = key[n + (i << 2)];
        }

        if i & 1 == 0 { &mut m_e } else { &mut m_o }.push(u32::from_le_bytes(pos));
    }

    for i in 0..k {
        let mut pos = [0u8; 8];
        for (n, b) in pos.iter_mut().enumerate() {
            *b = key[(i << 3) + n];
        }

        s.push(mulrs(pos));
    }

    let s = s.into_iter().rev().collect::<Vec<u32>>();

    let rho = (1 << 24) | (1 << 16) | (1 << 8) | 1;

    let mut res = [0u32; 40];

    for i in 0..20 {
        let a_i = h(i * rho * 2, &m_e);
        let b_i = h((2 * i + 1) * rho, &m_o).rotate_left(8);
        res[(i as usize) * 2] = sum!(a_i, b_i);
        res[(i * 2) as usize + 1] = sum!(a_i, b_i.overflowing_mul(2).0).rotate_left(9);
    }

    (Box::new(res), s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_block() {
        let mut bytes = [0u8; 16];
        for (n, i) in bytes.iter_mut().enumerate() {
            *i = n as u8;
        }

        let converted = convert_to_block(&bytes);
        let back = convert_from_block(converted);

        assert_eq!(back[..], bytes[..]);
    }

    #[test]
    fn test_encryption() {
        // let key = pbkdf2(b"password".to_vec(), (0..16).collect(), 1000, 256);
        let key: Vec<u8> = std::iter::repeat(0).take(16).collect::<Vec<u8>>();
        let twofish = Twofish::new(&key[..]);

        let expected_key: [u32; 40] = [
            0x52C54DDE, 0x11F0626D, 0x7CAC9D4A, 0x4D1B4AAA, 0xB7B83A10, 0x1E7D0BEB, 0xEE9C341F,
            0xCFE14BE4, 0xF98FFEF9, 0x9C5B3C17, 0x15A48310, 0x342A4D81, 0x424D89FE, 0xC14724A7,
            0x311B834C, 0xFDE87320, 0x3302778F, 0x26CD67B4, 0x7A6C6362, 0xC2BAF60E, 0x3411B994,
            0xD972C87F, 0x84ADB1EA, 0xA7DEE434, 0x54D2960F, 0xA2F7CAA8, 0xA6B8FF8C, 0x8014C425,
            0x6A748D1C, 0xEDBAF720, 0x928EF78C, 0x0338EE13, 0x9949D6BE, 0xC8314176, 0x07C07D68,
            0xECAE7EA7, 0x1FE71844, 0x85C05C89, 0xF298311E, 0x696EA672,
        ];

        assert_eq!(twofish.k[..], expected_key[..]);

        let exprected_encrypted: [u8; 16] = [
            0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8,
            0xC3, 0x5A,
        ];

        let mut ciphertext = [0u8; 16];

        twofish.encrypt_block(&mut ciphertext[..]);

        assert_eq!(&ciphertext[..], &exprected_encrypted[..]);
    }

    #[test]
    fn test_decryption() {
        let key: Vec<u8> = std::iter::repeat(0).take(16).collect::<Vec<u8>>();
        let twofish = Twofish::new(&key[..]);
        let mut encrypted: [u8; 16] = [
            0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8,
            0xC3, 0x5A,
        ];

        twofish.decrypt_block(&mut encrypted[..]);

        let exprected_decrypted = [0u8; 16];

        assert_eq!(&encrypted[..], &exprected_decrypted[..])
    }

    #[test]
    fn endianess() {
        let k = 1817234060u32;
        let j = k.to_le_bytes();
        let mut z = [0u8; 4];
        for i in 0..4 {
            z[i] = (k >> (8 * i)) as u8 & 255u8;
        }
        assert_eq!(z, j);
    }
}
