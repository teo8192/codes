use num_bigint::{BigUint, RandBigInt, ToBigUint};

fn rabin_miller(number: BigUint, rounds: u32) -> Option<BigUint> {
    let big = |x: u32| x.to_biguint().unwrap();

    if &number & big(1) == big(0) {
        return if number == big(2) { Some(big(2)) } else { None };
    }

    let mut s = 0;
    let mut d = &number - big(1);

    while &d & big(1) == big(0) {
        s += 1;
        d >>= 1;
    }

    let mut rng = rand::thread_rng();

    'witness: for _ in 0..rounds {
        let a: BigUint = rng.gen_biguint_range(&big(2), &(&number - big(2)));
        let mut x = a.modpow(&d, &number);

        if x == big(1) || x == &number - big(1) {
            continue 'witness;
        }

        for _ in 0..s - 1 {
            x = x.modpow(&big(2), &number);
            if x == big(1) {
                break;
            } else if x == &number - big(1) {
                continue 'witness;
            }
        }
        return None;
    }

    Some(number)
}

#[cfg(test)]
mod tests {
    use super::rabin_miller;
    use num_bigint::{BigUint, ToBigUint};

    #[test]
    fn primes() {
        let big = |x: u32| x.to_biguint().unwrap();
        assert_eq!(rabin_miller(big(7), 7), Some(big(7)));
        assert_eq!(rabin_miller(big(2), 7), Some(big(2)));
        assert_eq!(rabin_miller(big(3), 7), Some(big(3)));
        assert_eq!(rabin_miller(big(5), 7), Some(big(5)));
        assert_eq!(rabin_miller(big(97), 7), Some(big(97)));
        let huge1 = BigUint::parse_bytes(b"1467923180967075294885675735323676324541564153049833999514232854190565004830812017605189214532225843264116066716156512318969593182391270344778455946362418431315473690995547662440406403933883702433889640683256385143897124931493130999543489479979982760588036516465704083985278537571062266513783550488204590596533270758336933062471517204351390932512929930039938399855920453507167563630259855360201535752462696373117449205677587173382012710734138423402290605978964689147279941717461016763730458182214831495000247921302462425413770606967457598565961362227488304184115780694889150848788831156212021631505646285419187", 10).unwrap();
        let huge2 = BigUint::parse_bytes(b"1467923180967075294885675735323676324541564153049833999514232854190565004830812017605189214532225843264116066716156512318969593182391270344778455946362418431315473690995547662440406403933883702433889640683256385143897124931493130999543489479979982760588036516465704083985278537571062266513783550488204590596533270758336933062471517204351390932512929930039938399855920453507167563630259855360201535752462696373117449205677587173382012710734138423402290605978964689147279941717461016763730458182214831495000247921302462425413770606967457598565961362227488304184115780694889150848788831156212021631505646285419187", 10).unwrap();
        assert_eq!(rabin_miller(huge1, 7), Some(huge2));
    }

    #[test]
    fn composites() {
        let big = |x: u32| x.to_biguint().unwrap();

        assert_eq!(rabin_miller(big(9), 7), None);
        assert_eq!(rabin_miller(big(95), 7), None);
    }
}
