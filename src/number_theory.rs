use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};

pub fn inverse(a: BigUint, modulus: BigUint) -> Option<BigUint> {
    if modulus == 0.to_biguint().unwrap() || a == 0.to_biguint().unwrap() {
        return None;
    }

    let big = |x: &dyn ToBigInt| x.to_bigint().unwrap();

    fn find(
        u: BigInt,
        g: BigInt,
        x: BigInt,
        y: BigInt,
        a: BigInt,
        modulus: BigInt,
    ) -> (BigInt, BigInt, BigInt) {
        if y == 0.to_bigint().unwrap() {
            let s = (&g - a * &u) / modulus;
            (g, u, s)
        } else {
            let t = &g % &y;
            let q = &g / &y;
            let s = &u - &q * &x;
            find(x, y, s, t, a, modulus)
        }
    }

    let (g, mut u, _) = find(
        big(&1),
        big(&a),
        big(&0),
        big(&modulus),
        big(&a),
        big(&modulus),
    );

    if g == big(&1) {
        while u < 0.to_bigint().unwrap() {
            u += modulus.to_bigint().unwrap();
        }
        Some(u.to_biguint().unwrap())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigUint, ToBigUint};

    fn big(x: u32) -> BigUint {
        x.to_biguint().unwrap()
    }

    #[test]
    fn inverse() {
        assert_eq!(super::inverse(big(5), big(11)), Some(big(9)));
        assert_eq!(super::inverse(big(6), big(9)), None);
    }
}
