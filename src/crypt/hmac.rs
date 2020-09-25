use super::sha::*;

const HMAC_LEN: usize = 64;

fn hmac(key: &Vec<u8>, text: &Vec<u8>) -> Box<[u8; HMAC_LEN]> {
    let mut k_0 = key.clone();
    let k_0 = if k_0.len() == HMAC_LEN {
        k_0
    } else if key.len() < HMAC_LEN {
        k_0.append(&mut std::iter::repeat(0).take(HMAC_LEN - key.len()).collect());
        k_0
    } else {
        let res: Box<[u8; HMAC_LEN]> = k_0.iter().map(|x| *x).hash();
        let mut out = Vec::new();
        for i in (*res).iter() {
            out.push(*i);
        }
        out
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

    let res: Box<[u8; HMAC_LEN]> = kxoripad.iter().map(|x| *x).hash();

    let mut kxoropad = Vec::new();

    for b in &k_0 {
        kxoropad.push(b ^ opad.next().unwrap());
    }

    kxoropad.append(&mut res.to_vec());

    kxoropad.iter().map(|x| *x).hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_test_1() {
        let input = b"Smaple message for keylen=blocklen".to_vec();
        let key = (0..0x80).collect();
        let mac = hmac(&key, &input);
        let exp = [
            0xFC, 0x25, 0xE2, 0x40, 0x65, 0x8C, 0xA7, 0x85, 0xB7, 0xA8, 0x11, 0xA8, 0xD3, 0xF7,
            0xB4, 0xCA, 0x48, 0xCF, 0xA2, 0x6A, 0x8A, 0x36, 0x6B, 0xF2, 0xCD, 0x1F, 0x83, 0x6B,
            0x05, 0xFC, 0xB0, 0x24, 0xBD, 0x36, 0x85, 0x30, 0x81, 0x81, 0x1D, 0x6C, 0xEA, 0x42,
            0x16, 0xEB, 0xAD, 0x79, 0xDA, 0x1C, 0xFC, 0xB9, 0x5E, 0xA4, 0x58, 0x6B, 0x8A, 0x0C,
            0xE3, 0x56, 0x59, 0x6A, 0x55, 0xFB, 0x13, 0x47,
        ];
        assert_eq!(mac[..], exp[..]);
    }
}
