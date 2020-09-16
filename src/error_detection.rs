fn encode_block(data: &[u8; 11]) -> [u8; 16] {
    let mut encoded = [0u8; 16];
    let mut c = 0;

    for i in 0..16 {
        if ![0, 1, 2, 4, 8].contains(&i) {
            encoded[i] = data[c];
            c += 1;
        }
    }

    for i in 0..4 {
        let pos = 2usize.pow(i);
        encoded[pos] = encoded
            .iter()
            .enumerate()
            .filter_map(|(num, bit)| if num & pos > 0 { Some(bit) } else { None })
            .fold(0, |n, i| n ^ i);
    }

    encoded[0] = encoded.iter().fold(0, |n, i| n ^ i);

    encoded
}

fn decode_block(data: &[u8; 16]) -> Vec<u8> {
    let mut localdata: [u8; 16] = [0; 16];
    for (i, bit) in data.iter().enumerate() {
        localdata[i] = *bit;
    }

    let pos = data
        .iter()
        .enumerate()
        .filter_map(|(num, bit)| if *bit == 1u8 { Some(num) } else { None })
        .fold(0, |n, i| n ^ i);
    if pos > 0 {
        println!("one bit flipped");
        localdata[pos] ^= 1;
    }

    if localdata.iter().fold(0, |n, i| n ^ i) == 1 {
        println!("two errors");
    }

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
        .collect()
}

fn compress_block(data: &[u8; 16]) -> [u8; 2] {
    let mut res = [0u8; 2];

    for i in 0..16 {
        let idx = if i & 0b1000 > 0 { 1 } else { 0 };
        res[idx] <<= 1;
        res[idx] |= data[i];
    }

    res
}

fn extract_block(data: &[u8; 2]) -> [u8; 16] {
    let mut res = [0u8; 16];

    for i in 0..16 {
        let idx = if i & 0b1000 > 0 { 1 } else { 0 };
        res[i] = if data[idx] & 2u8.pow(7 - (i & 7) as u32) > 0 {
            1
        } else {
            0
        };
    }

    res
}

struct Bytes<'a> {
    bytes: &'a [u8],
}

struct BytesIterator<'a, 'b> {
    bytes: &'a Bytes<'b>,
    pos: usize,
}

impl<'a> Bytes<'a> {
    fn new(bytes: &[u8]) -> Bytes {
        Bytes { bytes }
    }

    fn iter(&self) -> BytesIterator {
        BytesIterator {
            bytes: &self,
            pos: 0,
        }
    }
}

impl<'a, 'b> Iterator for BytesIterator<'a, 'b> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        let byte = self.pos >> 3;
        let offset: usize = 7 - (self.pos & 7);
        if byte >= self.bytes.bytes.len() {
            return None;
        }
        self.pos += 1;
        Some(if self.bytes.bytes[byte] & 2u8.pow(offset as u32) > 0 {
            1
        } else {
            0
        })
    }
}

fn encode(data: Bytes) -> Vec<[u8; 2]> {
    let mut byte_stream = data.iter();
    let mut out = Vec::new();
    let mut b = [0u8; 11];
    let mut end = false;

    while !end {
        let mut i = 0;
        while let Some(bit) = byte_stream.next() {
            b[i] = bit;
            i += 1;
            if i >= 11 {
                break;
            }
        }
        while i < 11 {
            b[i] = 0;
            i += 1;
            end = true;
        }

        out.push(compress_block(&encode_block(&b)));
    }

    out
}

fn decode(data: Vec<[u8; 2]>) -> Vec<u8> {
    let mut bytes = Vec::new();

    let mut iter = 0;

    for i in 0..data.len() {
        let b = extract_block(&data[i]);
        let block = decode_block(&b);

        for bit in block {
            if iter & 7 == 0 {
                bytes.push(0);
            }

            let byte = iter >> 3;
            let offset = 7 - (iter & 7);

            if bit > 0 {
                bytes[byte] |= 2u8.pow(offset as u32);
            }

            iter += 1;
        }
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_block() {
        let c = [1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1];
        let mut code = encode_block(&c);
        assert_eq!(code, [0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1]);
        code[1] ^= 1;
        let decoded = decode_block(&code);
        assert_eq!(decoded, c);
    }

    #[test]
    fn block_compression() {
        let block = [1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0];
        let compressed = compress_block(&block);
        assert_eq!(compressed, [0b11010100, 0b11101000])
    }

    #[test]
    fn test_stream() {
        let bytes = b"hello motherfucker";
        let encoded = encode(Bytes::new(bytes));
        let decoded = decode(encoded);
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
