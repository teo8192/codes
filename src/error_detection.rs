use std::convert::TryInto;

/// if i is a bit-index, then this
/// function returns the (idx, off)
/// index of the desired byte and
/// the offset in the byte
#[inline]
fn split(i: usize) -> (usize, u8) {
    (i >> 3, 7 - (i as u8 & 7))
}

/// this function takes 11 bits of data and converts them
/// to a 16 bit block.
fn encode_block(data: &[u8; 11]) -> [u8; 2] {
    let mut encoded = [0u8; 16];
    let mut c = 0;
    let mut res = [0u8; 2];

    // write data into the correct spot.
    for i in 0..16 {
        if ![0, 1, 2, 4, 8].contains(&i) {
            encoded[i] = data[c];
            c += 1;
        }
    }

    // write the parity bits
    for i in 0..4 {
        let pos = 1 << i;
        encoded[pos] = encoded
            .iter()
            .enumerate()
            .filter_map(|(num, bit)| if num & pos > 0 { Some(bit) } else { None })
            .fold(0, |n, i| n ^ i);
    }

    // write the last parity bit to spot more errors.
    encoded[0] = encoded.iter().fold(0, |n, i| n ^ i);

    for i in 0..16 {
        let (idx, _) = split(i);
        res[idx] <<= 1;
        res[idx] |= encoded[i];
    }

    res
}

/// decode a block into a vector containing 11 bits.
/// sould be rewritten to be either return an array of 11 bits
/// or better yet: an iterator! Then the flat_map could work geiniously!
fn decode_block(data: &[u8; 2]) -> Option<Vec<u8>> {
    // split the two bytes into 16 bits
    let mut localdata: Vec<u8> = (0..16)
        .map(|i| {
            let (idx, off) = split(i);
            (data[idx] >> off) & 1
        })
        .collect();

    // find the position of an possibly flipped bit
    let pos = localdata
        .iter()
        .enumerate()
        .filter_map(|(num, bit)| if *bit == 1 { Some(num) } else { None })
        .fold(0, |n, i| n ^ i);

    if pos > 0 {
        localdata[pos] ^= 1;
    }

    // verify the total parity
    // added the pos > 0 for it not to crash of bit 0 was the only bit flipped.
    if localdata.iter().fold(0, |n, i| n ^ i) == 1 && pos > 0 {
        None
    } else {
        Some(
            // here the localdata is filtered
            // to remove the parity bits
            localdata
                .iter()
                .enumerate()
                .filter_map(|(num, bit)| {
                    if [0, 1, 2, 4, 8].contains(&num) {
                        None
                    } else {
                        Some(bit)
                    }
                })
                .map(|x| *x)
                .collect(),
        )
    }
}

/// encode a bytes object.
/// TODO: change to Vec<u8>
pub fn encode(data: Vec<u8>) -> Vec<[u8; 2]> {
    let convert = |rest: &mut Vec<u8>| encode_block(
                        (&(rest.drain(0..11).collect::<Vec<u8>>())[..])
                            .try_into()
                            .expect("wrong length?!?"),
                    );

    let (mut rest, mut output) =
        data.iter()
            .fold((Vec::new(), Vec::new()), |(mut rest, mut output), elem| {
                for i in 0..8 {
                    rest.push((elem >> (7 - i)) & 1);
                }
                if rest.len() >= 11 {
                    output.push(convert(&mut rest))
                }
                (rest, output)
            });

    // if rest is not drained, pad with zeroes and push to output.
    if rest.len() > 0 {
        while rest.len() < 11 {
            rest.push(0);
        }
        output.push(convert(&mut rest))
    }

    output
}

/// decodes a vector of byte-tuples into a proper byte vector
pub fn decode(data: Vec<[u8; 2]>) -> Result<Vec<u8>, Vec<u8>> {
    let mut bytes = Vec::new();

    let mut iter = 0;

    for i in 0..data.len() {
        // try to decode the block.
        // if not, empty vector, the byte is skipped.
        if let Some(block) = decode_block(&data[i]) {
            for bit in block {
                // bitwise and of 2^n - 1 is the same as mod(2^n)
                if iter & 7 == 0 {
                    bytes.push(0);
                }

                let (idx, off) = split(iter);

                bytes[idx] |= (bit & 1) << off;

                iter += 1;
            }
        } else {
            return Err(bytes);
        }
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_block_no_error() {
        let c = [1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1];
        let code = encode_block(&c);
        assert_eq!(code, [0b00111100, 0b01101001]);
        assert_eq!(decode_block(&code).unwrap(), c);
    }

    #[test]
    fn code_block_one_error() {
        let c = [1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1];
        let mut code = encode_block(&c);
        assert_eq!(code, [0b00111100, 0b01101001]);
        code[0] ^= 0b00001000;
        assert_eq!(decode_block(&code).unwrap(), c);
    }

    #[test]
    fn code_block_two_error() {
        let c = [1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1];
        let mut code = encode_block(&c);
        assert_eq!(code, [0b00111100, 0b01101001]);
        code[0] ^= 0b00001000;
        code[1] ^= 0b00100000;
        assert_eq!(decode_block(&code), None);
    }

    #[test]
    fn test_stream() {
        use std::hash::{Hash, Hasher, SipHasher};
        let bytes = b"hello motherfucker";
        let encoded = encode(bytes.to_vec());
        println!("{:?}", encoded);
        let decoded = decode(
            encoded
                .iter()
                .enumerate()
                .map(|(n, bytes)| {
                    // flip a bit of every other byte. See how you like them apples.

                    // use a has to get a pseudorandom bit
                    let mut hasher = SipHasher::new();
                    n.hash(&mut hasher);
                    bytes.hash(&mut hasher);
                    let mut k = hasher.finish() as usize;
                    let idx = k & 1;
                    // k >>= 1;

                    let mut b = [0; 2];

                    b[idx] = bytes[idx] ^ (1 << (k & 7));
                    b[1 ^ idx] = bytes[1 ^ idx];

                    b
                })
                .collect(),
        )
        .expect("To many errors to correct!");
        // all this doo dad to remove the zero that is at the end.
        let b: Vec<u8> = decoded
            .iter()
            .rev()
            .skip_while(|x| **x == 0)
            .map(|x| *x)
            .collect::<Vec<u8>>()
            .iter()
            .map(|x| *x)
            .rev()
            .collect();
        assert_eq!(b, bytes);
    }
}
