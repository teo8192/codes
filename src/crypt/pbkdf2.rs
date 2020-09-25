use crate::crypt::sha::Hash;

fn round(password: &Vec<u8>, salt: &Vec<u8>, count: usize, i: usize) -> Box<[u8; 32]> {
    let mut result = Box::new([0u8; 32]);
    let mut tmp_0: Box<[u8; 32]> = password
        .iter()
        .chain(salt.iter())
        .chain(format!("{}", i).into_bytes().iter())
        .map(|x| *x)
        .hash();
    for _ in 1..count {
        let tmp: Box<[u8; 32]> = password.iter().chain(tmp_0.iter()).map(|x| *x).hash();
        for (i, b) in tmp.iter().enumerate() {
            result[i] ^= b;
        }
        tmp_0 = tmp;
    }
    result
}

/// password is the password
/// salt is a salt
/// dklen is the derived key length
/// c is the iteration count
/// hash is the hash funciton
/// hlen is the bit length of the hash function
pub fn pbkdf2(password: Vec<u8>, salt: Vec<u8>, c: usize, dklen: usize) -> Vec<u8> {
    debug_assert!(dklen <= ((1 << 32) - 1) * 256, "derived key too long");
    let l = dklen / 256 + if dklen % 256 != 0 { 1 } else { 0 };
    let mut res = Vec::new();
    let mut counter = 0;
    'outer: for block in (0..l).map(|i| round(&password, &salt, c, i)) {
        for b in block.iter() {
            if counter * 8 >= dklen {
                break 'outer;
            }
            res.push(*b);
            counter += 1;
        }
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2() {
        let password = b"hunter10".to_vec();
        let salt: Vec<u8> = (0..16).collect();

        let result = pbkdf2(password, salt, 10000, 256);
        println!("{:?}", result);
        assert!(false);
    }
}
