use num_bigint::{BigUint, RandBigInt, ToBigUint};
use rand::Rng;

fn rabin_miller(number: BigUint, rounds: u32) -> Option<BigUint> {
    let big = |x: u32| x.to_biguint().unwrap();

    println!("got: {}", number);

    if number < big(10) {
        return if [big(2), big(3), big(5), big(7)].contains(&number) {
            Some(number)
        } else {
            None
        };
    } else if &number & big(1) == big(0) {
        return None;
    }

    let mut s = 0;
    let mut d = &number - big(1);

    while &d & big(1) == big(0) {
        s += 1;
        d >>= 1;
    }

    // should be fine, since d=log_2 (number), will only overflow if number is absurdly large
    // (larger that the memory of my conputer, gotta be 2^2^32 bits)
    let d = d.to_u32_digits()[0];

    let mut rng = rand::thread_rng();

    'witness: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&big(2), &(&number - big(2)));
        println!("{}", &a);
        let mut x = a.pow(d) % &number;

        println!("x: {}", x);

        if x == big(1) || x == &number - big(1) {
            continue 'witness;
        }

        'inner: for _ in 0..s - 1 {
            let square = |x| &x * &x;
            x = square(x) % &number;
            println!("{}, {}", x, s);
            if x == big(1) {
                break 'inner;
            } else if x == &number - big(1) {
                continue 'witness;
            }
        }
        println!("hax x as {}", x);
        return None;
    }

    Some(number)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        use super::rabin_miller;
        use num_bigint::ToBigUint;
        let big = |x: u32| x.to_biguint().unwrap();
        assert_eq!(rabin_miller(big(9), 7), None);
        assert_eq!(rabin_miller(big(7), 7), Some(big(7)));
        assert_eq!(rabin_miller(big(97), 7), Some(big(97)));
        assert_eq!(rabin_miller(big(95), 7), None);
    }
}
