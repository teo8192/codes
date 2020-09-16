pub fn encode_block(data: &[u8; 11]) -> [u8; 16] {
    let mut encoded = [0u8; 16];
    let mut c = 0;

    for i in 0..15 {
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

pub fn decode_block(data: &[u8; 16]) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    #[test]
    fn hamming_codes() {
        let c = [1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0];
        let mut code = super::encode_block(&c);
        assert_eq!(code, [1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0]);
        code[1] ^= 1;
        let decoded = super::decode_block(&code);
        assert_eq!(decoded, c);
    }
}
