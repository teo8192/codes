//! Currently SHA512 implemented by [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) standard.
//!
//! here is an example:
//!
//!     # use codes::crypt::sha::*;
//!     let hash = HashAlg::Sha512;
//!     let digest = hash.hash(b"Lorem ipsum dolor sit amet.");

pub enum HashAlg {
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
}

// {{{ Macros for computation

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

macro_rules! rotr {
    ($n:expr, $x:expr) => {{
        $x.rotate_right($n)
    }};
}

macro_rules! shr {
    ($n:expr, $x:expr) => {{
        $x >> $n
    }};
}

macro_rules! ch {
    ($x:expr, $y:expr, $z:expr) => {{
        ($x & $y) ^ (!$x & $z)
    }};
}

macro_rules! maj {
    ($x:expr, $y:expr, $z:expr) => {{
        ($x & $y) ^ ($x & $z) ^ ($z & $y)
    }};
}

macro_rules! sum0512 {
    ($x:expr) => {{
        rotr!(28, $x) ^ rotr!(34, $x) ^ rotr!(39, $x)
    }};
}

macro_rules! sum1512 {
    ($x:expr) => {{
        rotr!(14, $x) ^ rotr!(18, $x) ^ rotr!(41, $x)
    }};
}

macro_rules! sigma0512 {
    ($x:expr) => {{
        rotr!(1, $x) ^ rotr!(8, $x) ^ shr!(7, $x)
    }};
}

macro_rules! sigma1512 {
    ($x:expr) => {{
        rotr!(19, $x) ^ rotr!(61, $x) ^ shr!(6, $x)
    }};
}
// }}}

// {{{ The K constant

const K512: [u64; 80] = [
    0x428a2f98d728ae22, //  0
    0x7137449123ef65cd, //  1
    0xb5c0fbcfec4d3b2f, //  2
    0xe9b5dba58189dbbc, //  3
    0x3956c25bf348b538, //  4
    0x59f111f1b605d019, //  5
    0x923f82a4af194f9b, //  6
    0xab1c5ed5da6d8118, //  7
    0xd807aa98a3030242, //  8
    0x12835b0145706fbe, //  9
    0x243185be4ee4b28c, // 10
    0x550c7dc3d5ffb4e2, // 11
    0x72be5d74f27b896f, // 12
    0x80deb1fe3b1696b1, // 13
    0x9bdc06a725c71235, // 14
    0xc19bf174cf692694, // 15
    0xe49b69c19ef14ad2, // 16
    0xefbe4786384f25e3, // 17
    0x0fc19dc68b8cd5b5, // 18
    0x240ca1cc77ac9c65, // 19
    0x2de92c6f592b0275, // 20
    0x4a7484aa6ea6e483, // 21
    0x5cb0a9dcbd41fbd4, // 22
    0x76f988da831153b5, // 23
    0x983e5152ee66dfab, // 24
    0xa831c66d2db43210, // 25
    0xb00327c898fb213f, // 26
    0xbf597fc7beef0ee4, // 27
    0xc6e00bf33da88fc2, // 28
    0xd5a79147930aa725, // 29
    0x06ca6351e003826f, // 30
    0x142929670a0e6e70, // 31
    0x27b70a8546d22ffc, // 32
    0x2e1b21385c26c926, // 33
    0x4d2c6dfc5ac42aed, // 34
    0x53380d139d95b3df, // 35
    0x650a73548baf63de, // 36
    0x766a0abb3c77b2a8, // 37
    0x81c2c92e47edaee6, // 38
    0x92722c851482353b, // 39
    0xa2bfe8a14cf10364, // 40
    0xa81a664bbc423001, // 41
    0xc24b8b70d0f89791, // 42
    0xc76c51a30654be30, // 43
    0xd192e819d6ef5218, // 44
    0xd69906245565a910, // 45
    0xf40e35855771202a, // 46
    0x106aa07032bbd1b8, // 47
    0x19a4c116b8d2d0c8, // 48
    0x1e376c085141ab53, // 49
    0x2748774cdf8eeb99, // 50
    0x34b0bcb5e19b48a8, // 51
    0x391c0cb3c5c95a63, // 52
    0x4ed8aa4ae3418acb, // 53
    0x5b9cca4f7763e373, // 54
    0x682e6ff3d6b2b8a3, // 55
    0x748f82ee5defb2fc, // 56
    0x78a5636f43172f60, // 57
    0x84c87814a1f0ab72, // 58
    0x8cc702081a6439ec, // 59
    0x90befffa23631e28, // 60
    0xa4506cebde82bde9, // 61
    0xbef9a3f7b2c67915, // 62
    0xc67178f2e372532b, // 63
    0xca273eceea26619c, // 64
    0xd186b8c721c0c207, // 65
    0xeada7dd6cde0eb1e, // 66
    0xf57d4f7fee6ed178, // 67
    0x06f067aa72176fba, // 68
    0x0a637dc5a2c898a6, // 69
    0x113f9804bef90dae, // 70
    0x1b710b35131c471b, // 71
    0x28db77f523047d84, // 72
    0x32caab7b40c72493, // 73
    0x3c9ebe0a15c9bebc, // 74
    0x431d67c49c100d4c, // 75
    0x4cc5d4becb3e42b6, // 76
    0x597f299cfc657e2a, // 77
    0x5fcb6fab3ad6faec, // 78
    0x6c44198c4a475817, // 79
];

// }}}

macro_rules! create_box {
    ($bytes:expr, $size:expr, $type:ty) => {{
        let mut output = Box::new([0u8; $size >> 3]);

        unsafe {
            std::ptr::copy(
                $bytes
                    .iter()
                    .fold(Vec::new(), |mut bytes, x| {
                        for i in (0..(8 as $type)).rev() {
                            bytes.push(((x >> (i << 3)) & 255) as u8)
                        }

                        bytes
                    })
                    .as_ptr(),
                output.as_mut_ptr(),
                $size >> 3,
            );
        }

        output
    }};
}

pub trait Hash<T> {
    fn hash(&self, data: T) -> Box<[u8]>;
    fn size(&self) -> usize;
}

impl<'a, I> Hash<I> for HashAlg
where
    I: IntoIterator<Item = &'a u8, IntoIter = std::slice::Iter<'a, u8>>,
{
    fn size(&self) -> usize {
        use HashAlg::*;

        match self {
            Sha512_224 => 224,
            Sha512_256 => 256,
            Sha384 => 384,
            Sha512 => 512,
        }
    }

    fn hash(&self, data: I) -> Box<[u8]> {
        use HashAlg::*;

        let mut iv = match self {
            Sha384 => [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            Sha512 => [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            Sha512_256 => [
                0x22312194FC2BF72C,
                0x9F555FA3C84C64C2,
                0x2393B86B6F53B151,
                0x963877195940EABD,
                0x96283EE2A88EFFE3,
                0xBE5E1E2553863992,
                0x2B0199FC2C85B8AA,
                0x0EB72DDC81C52CA2,
            ],
            Sha512_224 => [
                0x8C3D37C819544DA2,
                0x73E1996689DCD4D6,
                0x1DFAB7AE32FF9C82,
                0x679DD514582F9FCF,
                0x0F6D2B697BD44DA8,
                0x77E36F7304C48942,
                0x3F9D85A86A1D36C8,
                0x1112E6AD91D692A1,
            ],
        };

        sha512_base(data.into_iter().copied(), &mut iv);

        match self {
            Sha512_224 => create_box!(iv, 224, u64),
            Sha512_256 => create_box!(iv, 256, u64),
            Sha384 => create_box!(iv, 384, u64),
            Sha512 => create_box!(iv, 512, u64),
        }
    }
}

fn sha512_base<I: Iterator<Item = u8>>(mut input: I, iv: &mut [u64; 8]) {
    let mut at_end = false;
    let mut added_one = false;
    let mut counter = 0u128;

    while !at_end {
        let mut m = [0u64; 16];
        let mut bytes: Vec<u8> = (&mut input).take(128).collect();

        if bytes.len() < 128 {
            if !added_one {
                counter += (bytes.len() as u128) << 3;
                bytes.push(1 << 7);
                added_one = true;
            }

            if bytes.len() > 112 {
                while bytes.len() < 128 {
                    bytes.push(0);
                }
            } else {
                while bytes.len() < 112 {
                    bytes.push(0);
                }

                bytes.append(&mut counter.to_be_bytes().to_vec());
                at_end = true;
            }
        } else {
            counter += 1024;
        }

        for (i, messbyte) in m.iter_mut().enumerate() {
            // let bidx = i << 3;
            let mut b = [0u8; 8];
            b[..8].clone_from_slice(&bytes[(i << 3)..((i + 1) << 3)]);
            *messbyte = u64::from_be_bytes(b);
            // for byte in bytes[(i << 3)..((i + 1) << 3)].iter().enumerate().map(|(n, byte)| byte.overflowing_shl(((7 - n) as u32) << 3).0) {
            //     *messbyte |= byte;
            // }

            // for n in 0..8 {
            //     *messbyte |= (bytes[bidx + n] as u64)
            //         .overflowing_shl(((7 - n) as u32) << 3)
            //         .0;
            // }
        }

        // for i in 0..16 {
        // }

        let mut a = iv[0];
        let mut b = iv[1];
        let mut c = iv[2];
        let mut d = iv[3];
        let mut e = iv[4];
        let mut f = iv[5];
        let mut g = iv[6];
        let mut h: u64 = iv[7];

        let mut w: Vec<u64> = Vec::new();

        for t in 0..80 {
            w.push(0);
            let next_w = if t < 16 {
                m[t]
            } else {
                sum!(
                    sigma1512!(w[t - 2]),
                    w[t - 7],
                    sigma0512!(w[t - 15]),
                    w[t - 16]
                )
            };
            w[t] = next_w;

            let t_1 = sum!(h, sum1512!(e), ch!(e, f, g), K512[t], w[t]);
            let t_2 = sum!(sum0512!(a), maj!(a, b, c));

            h = g;
            g = f;
            f = e;
            e = sum!(d, t_1);
            d = c;
            c = b;
            b = a;
            a = sum!(t_1, t_2);
        }

        iv[0] = sum!(a, iv[0]);
        iv[1] = sum!(b, iv[1]);
        iv[2] = sum!(c, iv[2]);
        iv[3] = sum!(d, iv[3]);
        iv[4] = sum!(e, iv[4]);
        iv[5] = sum!(f, iv[5]);
        iv[6] = sum!(g, iv[6]);
        iv[7] = sum!(h, iv[7]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_occifial() {
        let result: [u8; 64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];

        let input = b"abc";
        let hash = HashAlg::Sha512;
        let output = hash.hash(input);

        assert_eq!(result[..], output[..]);
    }

    #[test]
    fn test_multiline_b() {
        let input: Vec<u8> = (0x61..0x6f).flat_map(|i| i..(i + 8)).collect();
        let hash = HashAlg::Sha512;
        let output = hash.hash(&input[..]);

        let expected = [
            0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA, 0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC,
            0x14, 0x3F, 0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1, 0x72, 0x99, 0xAE, 0xAD,
            0xB6, 0x88, 0x90, 0x18, 0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4, 0x33, 0x1B,
            0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A, 0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
            0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09,
        ];

        assert_eq!(output[..], expected[..]);
    }

    #[test]
    fn test_sha512_256() {
        let input = b"Unde labore cumque quos iure aut ipsa. Voluptatem non explicabo voluptatem nesciunt pariatur vel. Aut asperiores molestiae quis.

Ad animi nobis et aut et odio provident. Et quidem et molestiae quidem adipisci quia. Dolore molestiae ut excepturi debitis. Debitis vel qui laborum voluptas.

Perferendis et et quis. Consequatur ad amet doloremque sint dolorem eligendi. At reiciendis suscipit similique sed nam neque consequatur. Qui et optio sequi occaecati. Deserunt id ab omnis ut rerum nobis consequatur.

Accusantium corrupti dolor adipisci quisquam dolorum qui aut eos. Adipisci enim veritatis explicabo mollitia enim. Repellat aut perspiciatis a amet.

Officiis et placeat alias voluptatem quasi non. Reiciendis qui quo mollitia occaecati. Molestiae iusto soluta voluptas quisquam vero a adipisci exercitationem. Consectetur harum sint ea. Distinctio et vero repellendus a.";
        let hash = HashAlg::Sha512_256;
        let output = hash.hash(input.iter());

        let expected = [
            0x09, 0xa4, 0xa7, 0xff, 0x2e, 0xa4, 0x7b, 0xa4, 0x2d, 0xd0, 0x63, 0xf5, 0x5a, 0xde,
            0x2e, 0x1f, 0x09, 0x30, 0x55, 0x74, 0x3c, 0x1e, 0x5b, 0x4c, 0x31, 0xf4, 0x3f, 0x13,
            0x00, 0xf4, 0xe6, 0xa2,
        ];

        assert_eq!(expected[..], output[..]);
    }

    #[test]
    fn testsha512_256_nist_spec() {
        let result: [u8; 32] = [
            0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E, 0x29, 0xB7, 0x6B, 0x4C,
            0x7D, 0xAB, 0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC, 0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31,
            0x07, 0xE7, 0xAF, 0x23,
        ];

        // let output: Box<[u8; 32]> = b"abc".iter().map(|x| *x).hash();
        let hash = HashAlg::Sha512_256;
        let output = hash.hash(b"abc");

        assert_eq!(result[..], output[..]);
    }

    #[test]
    fn testsha512_256_nist_spec_long() {
        let result: [u8; 32] = [
            0x39, 0x28, 0xE1, 0x84, 0xFB, 0x86, 0x90, 0xF8, 0x40, 0xDA, 0x39, 0x88, 0x12, 0x1D,
            0x31, 0xBE, 0x65, 0xCB, 0x9D, 0x3E, 0xF8, 0x3E, 0xE6, 0x14, 0x6F, 0xEA, 0xC8, 0x61,
            0xE1, 0x9B, 0x56, 0x3A,
        ];

        let input: Vec<u8> = (0x61..0x6f).flat_map(|i| i..(i + 8)).collect();
        let hash = HashAlg::Sha512_256;
        let output = hash.hash(&input[..]);

        assert_eq!(result[..], output[..]);
    }

    #[test]
    fn testsha384() {
        let result: [u8; 48] = [
            0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6,
            0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A,
            0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA,
            0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
        ];

        let hash = HashAlg::Sha384;
        let output = hash.hash(b"abc");
        // let output: Box<[u8; 48]> = b"abc".iter().map(|x| *x).hash();

        assert_eq!(result[..], output[..]);
    }

    #[test]
    fn testsha384_long() {
        let result: [u8; 48] = [
            0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD,
            0x1B, 0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2, 0x2F, 0xA0, 0x80, 0x86,
            0xE3, 0xB0, 0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3,
            0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39,
        ];

        let input: Vec<u8> = (0x61..0x6f).flat_map(|i| i..(i + 8)).collect();
        let hash = HashAlg::Sha384;
        let output = hash.hash(&input[..]);

        assert_eq!(result[..], output[..]);
    }

    #[test]
    fn testsha512_224() {
        let result: [u8; 28] = [
            0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54, 0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08,
            0x42, 0xE2, 0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4, 0x3E, 0x89, 0x24, 0xAA,
        ];

        let hash = HashAlg::Sha512_224;
        let output = hash.hash(b"abc");

        assert_eq!(result[..], output[..]);
    }

    #[test]
    fn testsha512_224_long() {
        let result: [u8; 28] = [
            0x23, 0xFE, 0xC5, 0xBB, 0x94, 0xD6, 0x0B, 0x23, 0x30, 0x81, 0x92, 0x64, 0x0B, 0x0C,
            0x45, 0x33, 0x35, 0xD6, 0x64, 0x73, 0x4F, 0xE4, 0x0E, 0x72, 0x68, 0x67, 0x4A, 0xF9,
        ];

        let input: Vec<u8> = (0x61..0x6fu8).flat_map(|i| i..(i + 8)).collect();

        let hash = HashAlg::Sha512_224;
        let output = hash.hash(&input[..]);

        assert_eq!(result[..], output[..]);
    }
}
