macro_rules! qr {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
        $a = $a.overflowing_add($b).0;
        $d ^= $a;
        $d = $d.rotate_left(16);

        $c = $c.overflowing_add($d).0;
        $b ^= $c;
        $b = $b.rotate_left(12);

        $a = $a.overflowing_add($b).0;
        $d ^= $a;
        $d = $d.rotate_left(8);

        $c = $c.overflowing_add($d).0;
        $b ^= $c;
        $b = $b.rotate_left(7);
    }};
}

macro_rules! quarter_round {
    ($state:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {{
        qr!($state[$a], $state[$b], $state[$c], $state[$d]);
    }};
}

macro_rules! double_round {
    ($state:expr) => {{
        quarter_round!($state, 0, 4, 8, 12);
        quarter_round!($state, 1, 5, 9, 13);
        quarter_round!($state, 2, 6, 10, 14);
        quarter_round!($state, 3, 7, 11, 15);
        quarter_round!($state, 0, 5, 10, 15);
        quarter_round!($state, 1, 6, 11, 12);
        quarter_round!($state, 2, 7, 8, 13);
        quarter_round!($state, 3, 4, 9, 14);
    }};
}

/// Nonce is a non-sectret that may be used only once per encryption.
pub fn chacha20_block(key: &[u8; 32], counter: &[u8; 8], nonce: &[u8; 8]) -> Box<[u8; 64]> {
    let blockconst = b"expand 32-byte k";
    let mut tmp = [0u8; 4];

    let mut state = [0u32; 16];

    for i in 0..4 {
        for j in 0..4 {
            tmp[i] = blockconst[(i << 2) + j];
        }
        state[i] = u32::from_le_bytes(tmp);
    }

    for i in 0..8 {
        for j in 0..4 {
            tmp[j] = key[j + (i << 2)];
        }
        state[i + 4] = u32::from_le_bytes(tmp);
    }

    for i in 0..2 {
        for j in 0..4 {
            tmp[j] = counter[j + (i << 2)];
        }
        state[i + 12] = u32::from_le_bytes(tmp);
    }

    for i in 0..2 {
        for j in 0..4 {
            tmp[j] = nonce[j + (i << 2)];
        }
        state[i + 14] = u32::from_le_bytes(tmp);
    }

    let mut init_state = state.clone();

    for _ in 0..10 {
        double_round!(init_state);
    }

    for (s, i) in state.iter_mut().zip(init_state.iter()) {
        *s = s.overflowing_add(*i).0;
    }

    let mut res = [0u8; 64];
    for i in 0..16 {
        let tmp = state[i].to_le_bytes();
        for j in 0..4 {
            res[(i << 2) + j] = tmp[j];
        }
    }

    Box::new(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_qr() {
        let mut a: u32 = 0x11111111;
        let mut b: u32 = 0x01020304;
        let mut c: u32 = 0x9b8d6f43;
        let mut d: u32 = 0x01234567;

        qr!(a, b, c, d);

        println!("{:08X}", a);
        println!("{:08X}", b);
        println!("{:08X}", c);
        println!("{:08X}", d);

        assert_eq!(a, 0xea2a92f4);
        assert_eq!(b, 0xcb1cf8ce);
        assert_eq!(c, 0x4581472e);
        assert_eq!(d, 0x5881c4bb);
    }

    #[test]
    fn test_state_quart() {
        let mut input: [u32; 16] = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
            0x2098d9d6, 0x91dbd320,
        ];

        let expected = [
            0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
            0x2098d9d6, 0x91dbd320,
        ];

        quarter_round!(input, 2, 7, 8, 13);

        assert_eq!(input, expected);
    }

    #[test]
    fn test_chacha() {
        let mut key = [0u8; 32];
        for (k, n) in key.iter_mut().zip(0..0x20) {
            *k = n;
        }
        let mut nonce = [0u8; 8];
        nonce[3] = 9;
        nonce[7] = 0x4a;
        let counter = [ 0,0,0,0,0,0,0,1 ];

        let enc = chacha20_block(&key, &counter, &nonce);

        // let expected = [
// 0x10,  0xf1,  0xe7,  0xe4,  0xd1,  0x3b,  0x59,  0x15,  0x50,  0x0f,  0xdd,  0x1f,  0xa3,  0x20,  0x71,  0xc4, 
// 0xc7,  0xd1,  0xf4,  0xc7,  0x33,  0xc0,  0x68,  0x03,  0x04,  0x22,  0xaa,  0x9a,  0xc3,  0xd4,  0x6c,  0x4e, 
// 0xd2,  0x82,  0x64,  0x46,  0x07,  0x9f,  0xaa,  0x09,  0x14,  0xc2,  0xd7,  0x05,  0xd9,  0x8b,  0x02,  0xa2, 
// 0xb5,  0x12,  0x9c,  0xd1,  0xde,  0x16,  0x4e,  0xb9,  0xcb,  0xd0,  0x83,  0xe8,  0xa2,  0x50,  0x3c,  0x4e, 
        // ];

        // assert_eq!(&enc[..], &expected[..]);
    }
}
