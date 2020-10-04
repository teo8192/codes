// this import implements some traits that is neccecary
#[allow(unused_imports)]
use rand_core::RngCore;

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
fn encode_block(data: &[u8]) -> [u8; 2] {
    debug_assert!(data.len() == 11);
    let mut encoded = [0u8; 16];
    let mut c = 0;
    let mut res = [0u8; 2];

    // write data into the correct spot.
    for (i, enc_bit) in encoded.iter_mut().enumerate() {
        if ![0, 1, 2, 4, 8].contains(&i) {
            *enc_bit = data[c];
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

    for (i, ecbit) in encoded.iter().enumerate() {
        let (idx, _) = split(i);
        res[idx] <<= 1;
        res[idx] |= ecbit;
    }

    res
}

/// decode a block into a vector containing 11 bits.
/// sould be rewritten to be either return an array of 11 bits
/// or better yet: an iterator! Then the flat_map could work geiniously!
fn decode_block(data: &[u8; 2]) -> Vec<u8> {
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
        println!("two errors");
    }
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
        .copied()
        .collect()
}

/// encode a bytes object.
pub fn encode(data: Vec<u8>) -> Vec<u8> {
    let encode_11 = |rest: &mut Vec<u8>| encode_block(&rest.drain(0..11).collect::<Vec<u8>>()[..]);

    let (mut rest, mut output) =
        data.iter()
            .fold((Vec::new(), Vec::new()), |(mut rest, mut output), elem| {
                // extract the bits of this byte
                rest.append(&mut (0..8).map(|i| ((elem) >> (7 - i)) & 1u8).collect());
                // if rest is more than a block, encode it
                if rest.len() >= 11 {
                    output.push(encode_11(&mut rest))
                }
                (rest, output)
            });

    // if rest is not drained, pad with zeroes and push to output.
    if !rest.is_empty() {
        while rest.len() < 11 {
            rest.push(0);
        }
        output.push(encode_11(&mut rest))
    }

    output
        .iter()
        .flat_map(|x| x.iter())
        .copied()
        .collect::<Vec<u8>>()
}

/// decodes a vector of byte-tuples into a proper byte vector
/// Might return trailing zeros
pub fn decode(data: Vec<u8>) -> Vec<u8> {
    // might be stuff in the rest, but this will only be trailing zeros.
    // since this is less that a byte of bits, it was probably not intentionally put there
    assert_eq!(data.len() & 1, 0);
    data.iter()
        .fold((Vec::new(), Vec::new()), |(mut rest, mut tuples), byte| {
            rest.push(*byte);
            if rest.len() >= 2 {
                let mut dual = [0u8; 2];
                for (i, b) in rest.drain(0..2).enumerate() {
                    dual[i] = b;
                }
                tuples.push(dual)
            }
            (rest, tuples)
        })
        .1
        .iter()
        .fold((Vec::new(), Vec::new()), |(mut rest, mut output), elem| {
            // append all decoded bytes
            rest.append(&mut decode_block(elem));
            // this could also be folded I guess
            while rest.len() >= 8 {
                // here 8 bits is combined into a byte
                output.push(rest.drain(0..8).fold(0, |byte, bit| (byte << 1) | bit));
            }
            (rest, output)
        })
        .1
}

pub struct ErrCorrEncoder<'a, I: Iterator<Item = u8>> {
    iterator: &'a mut I,
    next: Option<u8>,
    rest_in_bits: Vec<u8>,
}

impl<'a, I: Iterator<Item = u8>> Iterator for ErrCorrEncoder<'a, I> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next.is_some() {
            let next = self.next;
            self.next = None;
            return next;
        }

        while self.rest_in_bits.len() < 11 {
            if let Some(next) = self.iterator.next() {
                self.rest_in_bits
                    .append(&mut (0..8).map(|i| ((next) >> (7 - i)) & 1u8).collect());
            } else if self.rest_in_bits.is_empty() {
                return None;
            } else {
                self.rest_in_bits.push(0)
            }
        }

        let bytes = encode_block(&self.rest_in_bits.drain(0..11).collect::<Vec<u8>>()[..]);
        self.next = Some(bytes[1]);

        Some(bytes[0])
    }
}

pub struct ErrCorrDecoder<'a, I: Iterator<Item = u8>> {
    iterator: &'a mut I,
    rest_bits: Vec<u8>,
}

impl<'a, I: Iterator<Item = u8>> Iterator for ErrCorrDecoder<'a, I> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest_bits.len() < 8 {
            let byte1 = self.iterator.next()?;
            self.rest_bits.append(&mut decode_block(&[
                byte1,
                if let Some(byte2) = self.iterator.next() {
                    byte2
                } else {
                    0
                },
            ]));
        }

        Some(
            self.rest_bits
                .drain(0..8)
                .fold(0, |byte, bit| (byte << 1) | bit),
        )
    }
}

pub trait ErrorDetection<'a, I: Iterator<Item = u8>> {
    fn encode(&mut self) -> ErrCorrEncoder<I>;
    fn decode(&mut self) -> ErrCorrDecoder<I>;
}

impl<'a, I: Iterator<Item = u8>> ErrorDetection<'a, I> for I {
    fn encode(&mut self) -> ErrCorrEncoder<I> {
        ErrCorrEncoder {
            iterator: self,
            next: None,
            rest_in_bits: Vec::new(),
        }
    }
    fn decode(&mut self) -> ErrCorrDecoder<I> {
        ErrCorrDecoder {
            iterator: self,
            rest_bits: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_block_no_error() {
        let c = [1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1];
        let code = encode_block(&c);
        assert_eq!(code, [0b00111100, 0b01101001]);
        assert_eq!(decode_block(&code), c);
    }

    #[test]
    fn code_block_one_error() {
        let c = [1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1];
        let mut code = encode_block(&c);
        assert_eq!(code, [0b00111100, 0b01101001]);
        code[0] ^= 0b00001000;
        assert_eq!(decode_block(&code), c);
    }

    #[test]
    fn code_block_two_error() {
        let c = [1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1];
        let mut code = encode_block(&c);
        assert_eq!(code, [0b00111100, 0b01101001]);
        code[0] ^= 0b00001000;
        code[1] ^= 0b00100000;
        assert!(decode_block(&code) != c);
    }

    fn run_stream_test(bytes: &mut Vec<u8>) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let encoded = encode(bytes.to_vec());
        println!("{:?}", encoded);
        let decoded = decode(
            encoded
                .iter()
                .enumerate()
                .map(|(n, bytes)| {
                    // flip a bit of every other byte. See how you like them apples.

                    let mut b = *bytes;
                    // use a has to get a pseudorandom bit
                    if n & 1 == 0 {
                        let mut hasher = DefaultHasher::new();
                        n.hash(&mut hasher);
                        bytes.hash(&mut hasher);
                        let k = hasher.finish() as usize;

                        b ^= 1 << (k & 7);
                    }

                    b
                })
                .collect(),
        );
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
        assert_eq!(&b, bytes);
    }

    #[test]
    fn test_stream() {
        run_stream_test(&mut b"hello motherfucker".to_vec());
        let limit = 8192;
        let mut rng = rand::thread_rng();
        for i in 0..limit {
            let mut v = Vec::with_capacity(i);
            rng.fill_bytes(&mut v[..]);
            run_stream_test(&mut v)
        }
    }

    #[test]
    fn test_hamming_iterators() {
        let teststring = b"hello motherfucker".to_vec();
        let kake: Vec<u8> = teststring.into_iter().encode().collect();
        let test: Vec<u8> = encode(b"hello motherfucker".to_vec());
        assert_eq!(test, kake);
        let kjartan: Vec<u8> = kake.into_iter().decode().collect();
        assert_eq!(kjartan, b"hello motherfucker\0");
    }
}
