//! The ChaCha20 cihper, based on the Salsa20 cipher.
//! This is a stream cipher.

use rayon::prelude::*;

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

// The counter is not added now, since that is the thing that is changed between each block.
fn initialize_block(key: &[u8; 32], nonce: &[u8; 8]) -> [u32; 16] {
    let mut block = [0u32; 16];
    let blockconst = b"expand 32-byte k";
    let mut tmp = [0u8; 4];

    // Add in the block constant
    for i in 0..4 {
        for j in 0..4 {
            tmp[j] = blockconst[(i << 2) + j];
        }
        block[i] = u32::from_le_bytes(tmp);
    }

    // add in the key
    for i in 0..8 {
        for j in 0..4 {
            tmp[j] = key[j + (i << 2)];
        }
        block[i + 4] = u32::from_le_bytes(tmp);
    }

    // add in the nonce
    for i in 0..2 {
        for j in 0..4 {
            tmp[j] = nonce[j + (i << 2)];
        }
        block[i + 14] = u32::from_le_bytes(tmp);
    }

    block
}

fn printblock(block: &[u32; 16]) {
    for (i, n) in block.iter().enumerate() {
        if i > 0 {
            if i & 3 == 0 {
                println!();
            }
        }

        print!("{:08X} ", n);
    }
}

fn hchacha(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut n = [0u8; 8];
    for (b, i) in n.iter_mut().zip(nonce[8..16].iter()) {
        *b = *i;
    }
    let mut block = initialize_block(key, &n);

    for i in 0..2 {
        let mut tmp = [0u8; 4];
        for j in 0..4 {
            tmp[j] = nonce[j + (i << 2)];
        }
        block[i + 12] = u32::from_le_bytes(tmp);
    }

    for _ in 0..10 {
        quarter_round!(block, 0, 4, 8, 12);
        quarter_round!(block, 1, 5, 9, 13);
        quarter_round!(block, 2, 6, 10, 14);
        quarter_round!(block, 3, 7, 11, 15);
        quarter_round!(block, 0, 5, 10, 15);
        quarter_round!(block, 1, 6, 11, 12);
        quarter_round!(block, 2, 7, 8, 13);
        quarter_round!(block, 3, 4, 9, 14);
    }

    let mut res = [0u8; 32];

    for i in 0..4 {
        let tmp = block[i].to_le_bytes();
        for j in 0..4 {
            res[(i << 2) + j] = tmp[j];
        }
    }

    for i in 0..4 {
        let tmp = block[i + 12].to_le_bytes();
        for j in 0..4 {
            res[16 + (i << 2) + j] = tmp[j];
        }
    }

    res
}

/// Nonce is a non-sectret that may be used only once per encryption.
///
/// Since this function is probably called multiple times in a row, it takes the result block as
/// the first argument instead of putting the result in a box. This is to save on heap allocations.
/// The in-block should be initialized, except for the counter.
pub fn chacha20_block(in_block: &[u32; 16], out_block: &mut [u8], counter: &[u32; 2]) {
    let mut state = *in_block;
    state[12..14].clone_from_slice(&counter[..]);

    // The init state is a copy of state, not a pointer to the same location.
    let mut init_state = state;

    // do the 20 rounds (10 double rounds)
    for _ in 0..10 {
        quarter_round!(init_state, 0, 4, 8, 12);
        quarter_round!(init_state, 1, 5, 9, 13);
        quarter_round!(init_state, 2, 6, 10, 14);
        quarter_round!(init_state, 3, 7, 11, 15);
        quarter_round!(init_state, 0, 5, 10, 15);
        quarter_round!(init_state, 1, 6, 11, 12);
        quarter_round!(init_state, 2, 7, 8, 13);
        quarter_round!(init_state, 3, 4, 9, 14);
    }

    debug_assert_ne!(init_state, state);

    // This is a non-bijectove addition, so is makes it particulary difficult to reverse the block
    for (s, i) in state.iter_mut().zip(init_state.iter()) {
        *s = s.overflowing_add(*i).0;
    }

    // convert the integers back to bytes
    let len = out_block.len();
    // round up
    let words = len >> 2 + if len & 3 > 0 { 1 } else { 0 };
    println!("words: {}", words);
    for i in 0..words {
        let tmp = state[i].to_le_bytes();
        // could be faster not doing this every time, but oh well
        for j in 0..min!(4, len - (i << 2)) {
            out_block[(i << 2) + j] ^= tmp[j];
        }
    }
}

pub struct XChaCha20 {
    key: Box<[u8; 32]>,
}

impl XChaCha20 {
    pub fn new(key: &[u8; 32]) -> Self {
        XChaCha20 {
            key: Box::new(*key),
        }
    }
}

impl Cipher<&mut [u8]> for XChaCha20 {
    /// Encrypt some text with the ChaCha20 stream cipher.
    /// The nonce has to be unique for every encryption.
    fn encrypt(&self, nonce: &[u8], plaintext: &mut [u8]) -> Result<(), String> {
        if nonce.len() != 24 {
            return Err(format!("nonce len is {} but should be 12.", nonce.len()));
        }
        // convert the nonce to an array instead of a slice
        // the input should maybe be an array, but oh well.
        let mut n = [0u8; 8];
        for (i, b) in nonce[16..24].iter().zip(n.iter_mut()) {
            *b = *i;
        }

        let mut hn = [0u8; 16];
        for (i, b) in nonce[0..16].iter().zip(hn.iter_mut()) {
            *b = *i;
        }

        let new_key = hchacha(&self.key, &hn);

        // the initial state of the cipher,
        // only missing the counter.
        // This is shared for all threads encrypting
        let block = initialize_block(&new_key, &n);

        // slice the plaintext up into blocks
        // and enumerate them. Then parallellize the operation
        // and encrypt/decrypt the block.
        plaintext
            .chunks_mut(64)
            .enumerate()
            .collect::<Vec<(usize, &mut [u8])>>()
            .into_par_iter()
            .for_each(|(n, mut plain_block)| {
                // start counting from 1
                let c = n + 1;
                // convert the usize counter to two u32.
                let counter = [(c >> 32) as u32, (c & ((1 << 32) - 1)) as u32];
                // encrypt the block
                chacha20_block(&block, &mut plain_block, &counter)
            });

        Ok(())
    }

    /// Decrypt something encrypted with ChaCha20.
    /// This is the same as encrypting it, so no worries
    fn decrypt(&self, nonce: &[u8], ciphertext: &mut [u8]) -> Result<(), String> {
        self.encrypt(nonce, ciphertext)
    }
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

impl Cipher<&mut [u8]> for ChaCha20 {
    /// Encrypt some text with the ChaCha20 stream cipher.
    /// The nonce has to be unique for every encryption.
    fn encrypt(&self, nonce: &[u8], plaintext: &mut [u8]) -> Result<(), String> {
        if nonce.len() != 8 {
            return Err(format!("nonce len is {} but should be 8.", nonce.len()));
        }
        // convert the nonce to an array instead of a slice
        // the input should maybe be an array, but oh well.
        let mut n = [0u8; 8];
        for (i, b) in nonce.iter().zip(n.iter_mut()) {
            *b = *i;
        }

        // the initial state of the cipher,
        // only missing the counter.
        // This is shared for all threads encrypting
        let block = initialize_block(&self.key, &n);

        // slice the plaintext up into blocks
        // and enumerate them. Then parallellize the operation
        // and encrypt/decrypt the block.
        plaintext
            .chunks_mut(64)
            .enumerate()
            .collect::<Vec<(usize, &mut [u8])>>()
            .into_par_iter()
            .for_each(|(n, mut plain_block)| {
                // start counting from 1
                let c = n + 1;
                // convert the usize counter to two u32.
                let counter = [(c >> 32) as u32, (c & ((1 << 32) - 1)) as u32];
                println!("{}", plain_block.len());
                // encrypt the block
                chacha20_block(&block, &mut plain_block, &counter)
            });

        Ok(())
    }

    /// Decrypt something encrypted with ChaCha20.
    /// This is the same as encrypting it, so no worries
    fn decrypt(&self, nonce: &[u8], ciphertext: &mut [u8]) -> Result<(), String> {
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
    fn test_chacha() -> Result<(), String> {
        let mut key = [0u8; 32];
        for (k, n) in key.iter_mut().zip(0..0x20) {
            *k = n;
        }
        let mut nonce = [0u8; 8];
        nonce[3] = 9;
        nonce[7] = 0x4a;

        let chacha20 = ChaCha20::new(&key);
        let plaintext = *b"kake smakere godt :D";
        let mut encrypted = plaintext;
        chacha20.encrypt(&nonce, &mut encrypted)?;

        assert_ne!(encrypted, plaintext);

        chacha20.decrypt(&nonce, &mut encrypted)?;

        assert_eq!(encrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_chacha_long() -> Result<(), String> {
        let mut key = [0u8; 32];
        for (k, n) in key.iter_mut().zip(0..0x20) {
            *k = n;
        }
        let mut nonce = [0u8; 8];
        nonce[3] = 9;
        nonce[7] = 0x4a;

        let chacha20 = ChaCha20::new(&key);
        let plaintext = *b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. In pretium magna commodo, posuere lacus nec, tempor mi. Etiam vel cursus massa, in ornare arcu. Vivamus tortor metus, blandit vitae ultricies in, eleifend vitae magna. Pellentesque iaculis arcu leo, eu faucibus ex ultricies sed. Suspendisse velit velit, viverra sit amet leo vitae, porttitor egestas elit. Duis ut imperdiet lectus, ac iaculis ex. Maecenas venenatis nibh in erat malesuada, non aliquam nisi ultrices. Maecenas egestas mollis rhoncus. Vestibulum nunc leo, malesuada ac ornare sed, rutrum vitae mi. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos.

            Vestibulum sagittis ullamcorper odio, vel luctus justo dapibus lobortis. Aliquam finibus interdum massa, eget auctor urna lacinia vel. Suspendisse congue velit quis justo porttitor fringilla. Quisque vel aliquam nibh, ut congue metus. Nullam maximus, ipsum et efficitur ornare, justo mi malesuada ante, vitae accumsan est neque a ante. Ut cursus sed ex id elementum. Nulla purus massa, hendrerit quis porttitor et, volutpat id metus. Curabitur eget egestas nisl, vitae sodales diam. Donec a sapien eleifend, congue massa ut, aliquet lectus. Nunc in fermentum mauris, in dignissim dolor. Vestibulum tempor sed ipsum mattis lobortis. Proin in tellus at elit finibus tempus vitae sit amet mi. Ut ut bibendum dolor. Mauris nisl tortor, dignissim in metus eu, blandit venenatis odio.

            Fusce dapibus ac odio quis consectetur. Ut at lectus euismod sapien pretium eleifend. Praesent id massa non dolor pretium lacinia ut quis arcu. Vestibulum quis lorem ac odio tempor vestibulum ac at purus. Aenean dignissim enim ut iaculis accumsan. Suspendisse eget magna vitae magna euismod elementum ultricies nec quam. Sed malesuada sollicitudin lectus sed lobortis. Integer nec sapien vel arcu interdum accumsan. Phasellus finibus ut ex in sollicitudin. Fusce vestibulum pellentesque leo, efficitur tempor metus condimentum in. Aliquam a mauris ac augue lobortis accumsan vitae vel turpis. Nulla tempor eros velit, at aliquam dui fermentum vitae.

            In felis nisi, congue a mattis eget, aliquet nec neque. Quisque venenatis ante in arcu scelerisque euismod. Cras mollis, lacus a iaculis porttitor, lacus erat fermentum justo, non molestie enim neque et magna. Praesent non ornare ipsum, et feugiat eros. In porttitor dictum lobortis. Cras luctus urna vel justo consequat, non vestibulum dui placerat. Curabitur est nunc, lobortis sed vehicula vitae, ornare a urna. Sed bibendum aliquam rutrum. Pellentesque sodales tellus orci, et volutpat justo condimentum eget. Praesent magna sapien, porttitor a ante id, vehicula rutrum tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam suscipit lorem ac interdum varius. Sed varius metus eu dapibus hendrerit. Fusce consequat egestas varius.";
        let mut encrypted = plaintext;
        chacha20.encrypt(&nonce, &mut encrypted)?;

        assert_ne!(encrypted[..], plaintext[..]);

        chacha20.decrypt(&nonce, &mut encrypted)?;

        assert_eq!(encrypted[..], plaintext[..]);

        Ok(())
    }

    #[test]
    fn hchacha_test() {
        let mut key = [0u8; 32];
        for (k, i) in key.iter_mut().zip(0..32) {
            *k = i;
        }
        let nonce: [u8; 16] = [
            00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59,
            0x27,
        ];
        let new_key = hchacha(&key, &nonce);
        let expected = [
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
            0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
            0x26, 0xd3, 0xec, 0xdc,
        ];
        assert_eq!(&new_key, &expected);
    }
}
