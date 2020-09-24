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

macro_rules! min {
    ($a:expr, $b:expr) => {{
        if $a < $b {
            $a
        } else {
            $b
        }
    }};
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
        ($x & $y) ^ (!($x as u64) & $z)
    }};
}

macro_rules! maj {
    ($x:expr, $y:expr, $z:expr) => {{
        ($x & $y) ^ ($x & $z) ^ ($z & $y)
    }};
}

macro_rules! sum0256 {
    ($x:expr) => {{
        rotr!(28, $x) ^ rotr!(34, $x) ^ rotr!(39, $x)
    }};
}

macro_rules! sum1256 {
    ($x:expr) => {{
        rotr!(14, $x) ^ rotr!(18, $x) ^ rotr!(41, $x)
    }};
}

macro_rules! sigma0256 {
    ($x:expr) => {{
        rotr!(1, $x) ^ rotr!(8, $x) ^ shr!(7, $x)
    }};
}

macro_rules! sigma1256 {
    ($x:expr) => {{
        rotr!(19, $x) ^ rotr!(61, $x) ^ shr!(6, $x)
    }};
}
// }}}

// {{{ The K cosntant

const K: [u64; 80] = [
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

fn sha512(mut input: Vec<u8>) -> Box<[u8; 64]> {
    #[allow(non_snake_case)]
    let mut H = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let mut at_end = input.len() == 0;
    let mut added_one = false;
    let l = (input.len() as u128) << 3;

    while !at_end {
        let mut m = [0u64; 16];
        let end = min!(128, input.len());
        let mut bytes: Vec<u8> = input.drain(0..end).collect();

        if bytes.len() < 128 {
            if !added_one {
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

                bytes.append(&mut l.to_be_bytes().to_vec());
                at_end = true;
            }
        }

        for i in 0..16 {
            let bidx = i << 3;
            for n in 0..8 {
                m[i] |= (bytes[bidx + n] as u64)
                    .overflowing_shl(((7 - n) as u32) << 3)
                    .0;
            }
        }

        let mut a = H[0];
        let mut b = H[1];
        let mut c = H[2];
        let mut d = H[3];
        let mut e = H[4];
        let mut f = H[5];
        let mut g = H[6];
        let mut h: u64 = H[7];

        let mut w: Vec<u64> = Vec::new();

        for t in 0..80 {
            w.push(0);
            let next_w = if t < 16 {
                m[t]
            } else {
                sum!(
                    sigma1256!(w[t - 2]),
                    w[t - 7],
                    sigma0256!(w[t - 15]),
                    w[t - 16]
                )
            };
            w[t] = next_w;

            let t_1 = sum!(h, sum1256!(e), ch!(e, f, g), K[t], w[t]);
            let t_2 = sum!(sum0256!(a), maj!(a, b, c));

            h = g;
            g = f;
            f = e;
            e = sum!(d, t_1);
            d = c;
            c = b;
            b = a;
            a = sum!(t_1, t_2);
        }

        H[0] = sum!(a, H[0]);
        H[1] = sum!(b, H[1]);
        H[2] = sum!(c, H[2]);
        H[3] = sum!(d, H[3]);
        H[4] = sum!(e, H[4]);
        H[5] = sum!(f, H[5]);
        H[6] = sum!(g, H[6]);
        H[7] = sum!(h, H[7]);
    }

    let mut output = Box::new([0u8; 64]);

    unsafe {
        std::ptr::copy(
            H.iter().fold(Vec::new(), |mut bytes, x| {
                for i in (0..8u64).rev() {
                    bytes.push(((x >> (i << 3)) & 255) as u8)
                }

                bytes
            })[..]
                .as_ptr(),
            output.as_mut_ptr(),
            64,
        );
    }

    output
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

        let output = sha512b(b"abc".to_vec());

        assert_eq!(result[..], output[..]);
    }

    #[test]
    fn test_multiline_b() {
        let input: Vec<u8> = (0x61..0x6f).flat_map(|i| i..(i + 8)).collect();

        let hash = sha512b(input);

        let expected = [
            0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA, 0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC,
            0x14, 0x3F, 0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1, 0x72, 0x99, 0xAE, 0xAD,
            0xB6, 0x88, 0x90, 0x18, 0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4, 0x33, 0x1B,
            0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A, 0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
            0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09,
        ];

        assert_eq!(hash[..], expected[..]);
    }
}
