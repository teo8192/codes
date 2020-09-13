use num_bigint::{BigUint, RandBigInt, ToBigUint};
use std::iter::Iterator;

fn big(num: u32) -> BigUint {
    num.to_biguint().unwrap()
}

fn rabin_miller(number: BigUint, rounds: u32) -> Option<BigUint> {
    let zero = big(0);
    let one = big(1);
    let two = big(2);

    if number < big(10) {
        return if number == big(2) ||
            number == big(3) || 
            number == big(5) || 
            number == big(7) {
                Some(number)
            } else {
                None
            };
    }

    if &number & &one == zero {
        return if number == two { Some(two) } else { None };
    }

    let mut s = 0;
    let mut d = &number - &one;

    while &d & &one == zero {
        s += 1;
        d >>= 1;
    }

    let mut rng = rand::thread_rng();

    'witness: for _ in 0..rounds {
        let a: BigUint = rng.gen_biguint_range(&two, &(&number - &two));
        let mut x = a.modpow(&d, &number);

        if x == one || x == &number - &one {
            continue 'witness;
        }

        for _ in 0..s - 1 {
            x = x.modpow(&two, &number);
            if x == one {
                break;
            } else if x == &number - &one {
                continue 'witness;
            }
        }
        return None;
    }

    Some(number)
}

#[derive(Debug)]
struct Prime {
    num: Option<BigUint>,
    size: u32
}

impl Prime {
    pub fn new(size: u32) -> Prime {
        Prime {
            num: None,
            size
        }
    }
}

impl Iterator for Prime {
    type Item = Prime;
    fn next(&mut self) -> Option<Prime> {
        let mut rng = rand::thread_rng();

        let mut num = rng.gen_biguint_range(&(big(1) << self.size - 1), &(big(1) << self.size));
        if &num & &big(1) == big(0) {
            num += big(1);
        }

        Some(Prime {
            num: std::iter::repeat(num)
                .enumerate()
                .map(|(n, num)| num + big((n as u32) << 1))
                .filter_map(|n| rabin_miller(n, 7))
                .next(),
                size: self.size
        })
    }
}

#[cfg(test)]
mod tests {
    use super::rabin_miller;
    use num_bigint::{BigUint, ToBigUint};

    fn big(x: u32) -> BigUint {
        x.to_biguint().unwrap()
    }

    #[test]
    fn primes() {
        assert_eq!(rabin_miller(big(7), 7), Some(big(7)));
        assert_eq!(rabin_miller(big(97), 7), Some(big(97)));
        let huge1 = BigUint::parse_bytes(b"1467923180967075294885675735323676324541564153049833999514232854190565004830812017605189214532225843264116066716156512318969593182391270344778455946362418431315473690995547662440406403933883702433889640683256385143897124931493130999543489479979982760588036516465704083985278537571062266513783550488204590596533270758336933062471517204351390932512929930039938399855920453507167563630259855360201535752462696373117449205677587173382012710734138423402290605978964689147279941717461016763730458182214831495000247921302462425413770606967457598565961362227488304184115780694889150848788831156212021631505646285419187", 10).unwrap();
        let huge2 = BigUint::parse_bytes(b"1467923180967075294885675735323676324541564153049833999514232854190565004830812017605189214532225843264116066716156512318969593182391270344778455946362418431315473690995547662440406403933883702433889640683256385143897124931493130999543489479979982760588036516465704083985278537571062266513783550488204590596533270758336933062471517204351390932512929930039938399855920453507167563630259855360201535752462696373117449205677587173382012710734138423402290605978964689147279941717461016763730458182214831495000247921302462425413770606967457598565961362227488304184115780694889150848788831156212021631505646285419187", 10).unwrap();
        assert_eq!(rabin_miller(huge1, 7), Some(huge2));
    }

    #[test]
    fn small_primes() {
        assert_eq!(rabin_miller(big(2), 7), Some(big(2)));
        assert_eq!(rabin_miller(big(3), 7), Some(big(3)));
        assert_eq!(rabin_miller(big(5), 7), Some(big(5)));
    }

    #[test]
    fn small_composites() {
        assert_eq!(rabin_miller(big(4), 7), None);
        assert_eq!(rabin_miller(big(6), 7), None);
    }

    #[test]
    fn composites() {
        assert_eq!(rabin_miller(big(9), 7), None);
        assert_eq!(rabin_miller(big(95), 7), None);
    }

    #[test]
    fn test_iter() {
        let size = 2048;

        if let Some(p) = super::Prime::new(size).next() {
            println!("{:?}", p);
        } else {
            println!("It failed?!?!?!?");
            assert!(false);
        }
    }
}
