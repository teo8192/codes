use super::sha::*;

const HMAC_LEN: usize = 64;
const SHA512_BLOCKSIZE: usize = 1024 >> 3;

pub fn hmac(key: &Vec<u8>, text: &Vec<u8>, tag_len: usize) -> Vec<u8> {
    debug_assert!(tag_len <= HMAC_LEN, "tag length exceeds hash length");
    let mut k_0 = key.clone();
    let hash = HashAlg::Sha512;

    if k_0.len() > SHA512_BLOCKSIZE {
        let res: Box<[u8]> = hash.hash(k_0.iter());
        let mut out = Vec::new();
        for i in (*res).iter() {
            out.push(*i);
        }
        k_0 = out;
    }

    let k_0 = if k_0.len() == SHA512_BLOCKSIZE {
        k_0
    } else {
        k_0.append(
            &mut std::iter::repeat(0)
                .take(SHA512_BLOCKSIZE - k_0.len())
                .collect(),
        );
        k_0
    };

    let mut ipad = std::iter::repeat(0x36);
    let mut opad = std::iter::repeat(0x5c);

    let mut kxoripad = Vec::new();

    for b in &k_0 {
        kxoripad.push(b ^ ipad.next().unwrap());
    }

    for b in text.iter() {
        kxoripad.push(*b);
    }

    let res = hash.hash(kxoripad.iter());

    let mut kxoropad = Vec::new();

    for b in &k_0 {
        kxoropad.push(b ^ opad.next().unwrap());
    }

    kxoropad.append(&mut res.to_vec());

    let mac = hash.hash(kxoropad.iter());

    mac[0..tag_len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_test_1() {
        let input = b"Sample message for keylen=blocklen".to_vec();
        let key = (0..0x80).collect();
        let mac = hmac(&key, &input, 64);
        let exp = [
            0xFC, 0x25, 0xE2, 0x40, 0x65, 0x8C, 0xA7, 0x85, 0xB7, 0xA8, 0x11, 0xA8, 0xD3, 0xF7,
            0xB4, 0xCA, 0x48, 0xCF, 0xA2, 0x6A, 0x8A, 0x36, 0x6B, 0xF2, 0xCD, 0x1F, 0x83, 0x6B,
            0x05, 0xFC, 0xB0, 0x24, 0xBD, 0x36, 0x85, 0x30, 0x81, 0x81, 0x1D, 0x6C, 0xEA, 0x42,
            0x16, 0xEB, 0xAD, 0x79, 0xDA, 0x1C, 0xFC, 0xB9, 0x5E, 0xA4, 0x58, 0x6B, 0x8A, 0x0C,
            0xE3, 0x56, 0x59, 0x6A, 0x55, 0xFB, 0x13, 0x47,
        ];
        assert_eq!(mac[..], exp[..]);
    }

    #[test]
    fn hmac_test_2() {
        let input = b"Sample message for keylen<blocklen".to_vec();
        let key = (0..0x40).collect();
        let mac = hmac(&key, &input, 64);
        let exp = [
            0xFD, 0x44, 0xC1, 0x8B, 0xDA, 0x0B, 0xB0, 0xA6, 0xCE, 0x0E, 0x82, 0xB0, 0x31, 0xBF,
            0x28, 0x18, 0xF6, 0x53, 0x9B, 0xD5, 0x6E, 0xC0, 0x0B, 0xDC, 0x10, 0xA8, 0xA2, 0xD7,
            0x30, 0xB3, 0x63, 0x4D, 0xE2, 0x54, 0x5D, 0x63, 0x9B, 0x0F, 0x2C, 0xF7, 0x10, 0xD0,
            0x69, 0x2C, 0x72, 0xA1, 0x89, 0x6F, 0x1F, 0x21, 0x1C, 0x2B, 0x92, 0x2D, 0x1A, 0x96,
            0xC3, 0x92, 0xE0, 0x7E, 0x7E, 0xA9, 0xFE, 0xDC,
        ];
        assert_eq!(mac[..], exp[..]);
    }

    #[test]
    fn hmac_test_3() {
        let input = b"Sample message for keylen=blocklen".to_vec();
        let key = (0..0xC8).collect();
        let mac = hmac(&key, &input, 64);
        let exp = [
            0xD9, 0x3E, 0xC8, 0xD2, 0xDE, 0x1A, 0xD2, 0xA9, 0x95, 0x7C, 0xB9, 0xB8, 0x3F, 0x14,
            0xE7, 0x6A, 0xD6, 0xB5, 0xE0, 0xCC, 0xE2, 0x85, 0x07, 0x9A, 0x12, 0x7D, 0x3B, 0x14,
            0xBC, 0xCB, 0x7A, 0xA7, 0x28, 0x6D, 0x4A, 0xC0, 0xD4, 0xCE, 0x64, 0x21, 0x5F, 0x2B,
            0xC9, 0xE6, 0x87, 0x0B, 0x33, 0xD9, 0x74, 0x38, 0xBE, 0x4A, 0xAA, 0x20, 0xCD, 0xA5,
            0xC5, 0xA9, 0x12, 0xB4, 0x8B, 0x8E, 0x27, 0xF3,
        ];
        assert_eq!(mac[..], exp[..]);
    }

    #[test]
    fn hmac_test_4() {
        let input = b"Sample message for keylen<blocklen, with truncated tag".to_vec();
        let key = (0..0x31).collect();
        let mac = hmac(&key, &input, 32);
        let exp = [
            0x00, 0xF3, 0xE9, 0xA7, 0x7B, 0xB0, 0xF0, 0x6D, 0xE1, 0x5F, 0x16, 0x06, 0x03, 0xE4,
            0x2B, 0x50, 0x28, 0x75, 0x88, 0x08, 0x59, 0x66, 0x64, 0xC0, 0x3E, 0x1A, 0xB8, 0xFB,
            0x2B, 0x07, 0x67, 0x78,
        ];
        assert_eq!(mac[..], exp[..]);
    }
}
