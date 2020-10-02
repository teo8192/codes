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

pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> Box<[u8; 64]> {
    let mut state = [0u32; 16];

    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for i in 0..8 {
        let mut tmp = [0u8; 4];
        for j in 0..4 {
            tmp[j] = key[j + (i << 2)];
        }
        state[i + 4] = u32::from_le_bytes(tmp);
    }

    state[12] = counter;

    for i in 0..3 {
        let mut tmp = [0u8; 4];
        for j in 0..4 {
            tmp[j] = nonce[j + (i << 2)];
        }
        state[i + 13] = u32::from_le_bytes(tmp);
    }

    let mut init_state = state.clone();

    for i in 0..16 {
        if i & 3 == 0 {
            println!("");
        }
        print!("{:08x} ", init_state[i]);
    }

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
        let mut nonce = [0u8; 12];
        nonce[3] = 9;
        nonce[7] = 0x4a;
        let block_count = 1;

        let enc = chacha20_block(&key, block_count, &nonce);

        let expected = [
            0x83, 0x77, 0x78, 0xab, 0xe2, 0x38, 0xd7, 0x63, 0xa6, 0x7a, 0xe2, 0x1e, 0x59, 0x50,
            0xbb, 0x2f, 0xc4, 0xf2, 0xd0, 0xc7, 0xfc, 0x62, 0xbb, 0x2f, 0x8f, 0xa0, 0x18, 0xfc,
            0x3f, 0x5e, 0xc7, 0xb7, 0x33, 0x52, 0x71, 0xc2, 0xf2, 0x94, 0x89, 0xf3, 0xea, 0xbd,
            0xa8, 0xfc, 0x82, 0xe4, 0x6e, 0xbd, 0xd1, 0x9c, 0x12, 0xb4, 0xb0, 0x4e, 0x16, 0xde,
            0x9e, 0x83, 0xd0, 0xcb, 0x4e, 0x3c, 0x50, 0xa2,
        ];

        assert_eq!(&enc[..], &expected[..]);
    }
}
