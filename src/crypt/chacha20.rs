use super::Cipher;

macro_rules! min {
    ($a:expr, $b:expr) => {{
        if $a < $b {
            $a
        } else {
            $b
        }
    }};
}

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

fn increment(counter: &mut [u8; 8]) {
    let mut idx = 0;
    let mut rollover = true;

    while rollover && idx < 8 {
        let (c, r) = counter[idx].overflowing_add(1);
        counter[idx] = c;
        rollover = r;

        idx += 1;
    }
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

pub struct ChaCha20 {
    key: Box<[u8; 32]>,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20 {
            key: Box::new(*key),
        }
    }
}

impl Cipher for ChaCha20 {
    /// Encrypt some text with the ChaCha20 stream cipher.
    /// The nonce has to be unique for every encryption.
    fn encrypt(&self, nonce: &Vec<u8>, plaintext: &mut Vec<u8>) -> Result<(), String> {
        if nonce.len() != 8 {
            return Err(format!("nonce len is {} but should be 8.", nonce.len()));
        }
        let mut counter = [0u8; 8];
        counter[0] = 1;
        let mut n = [0u8; 8];
        for (i, b) in nonce.iter().zip(n.iter_mut()) {
            *b = *i;
        }

        let len = plaintext.len();
        // ceil(divide by 64)
        let blocks = len >> 6 + if len & 63 == 0 { 0 } else { 1 };

        for i in 0..blocks {
            let enc = chacha20_block(&self.key, &counter, &n);
            increment(&mut counter);
            for j in 0..min!(len - (i << 6), 64) {
                plaintext[(i << 6) + j] ^= enc[j];
            }
        }

        Ok(())
    }

    /// Decrypt something encrypted with ChaCha20.
    /// This is the same as encrypting it, so no worries
    fn decrypt(&self, nonce: &Vec<u8>, ciphertext: &mut Vec<u8>) -> Result<(), String> {
        self.encrypt(nonce, ciphertext)
    }
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
        let counter = [0, 0, 0, 0, 0, 0, 0, 1];

        let _enc = chacha20_block(&key, &counter, &nonce);
    }
}
