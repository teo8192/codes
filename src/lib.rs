#![feature(test)]
extern crate test;

/// This is a test library for me to exprerement
/// both with Rust and with information theory.
/// The goal is to implement error detecting codes,
/// encryption and possibly compression.
/// Might also look at more shit on the way.
extern crate rayon;

pub mod cryptography;
pub mod error_detection;
pub mod number_theory;
pub mod prime;

#[cfg(test)]
mod tests {
    use super::prime::{PrimeGenerator, Primes};
    use num_bigint::{BigUint, ToBigUint};
    use test::Bencher;

    #[bench]
    fn generation512(b: &mut Bencher) {
        let mut rng = rand::thread_rng();

        let mut g = PrimeGenerator::new(512, &mut rng);

        b.iter(|| g.next());
    }

    #[bench]
    fn generation128(b: &mut Bencher) {
        let mut rng = rand::thread_rng();

        let mut g = PrimeGenerator::new(128, &mut rng);

        b.iter(|| g.next());
    }

    #[bench]
    fn generation1024(b: &mut Bencher) {
        let mut rng = rand::thread_rng();

        let mut g = PrimeGenerator::new(1024, &mut rng);

        b.iter(|| g.next());
    }

    #[bench]
    fn eratothosenes_small(b: &mut Bencher) {
        b.iter(|| {
            Primes::new()
                .take_while(|x| x < &10000)
                .map(|n| n.to_biguint().unwrap())
                .collect::<Vec<BigUint>>()
        });
    }

    #[bench]
    fn dist_range_small(b: &mut Bencher) {
        b.iter(|| {
            Primes::prime_range(
                0.to_biguint().unwrap(),
                10000.to_biguint().unwrap(),
                1.to_biguint().unwrap(),
            )
        });
    }

    #[bench]
    fn eratothosenes_medium(b: &mut Bencher) {
        let from = 100000;
        let to = from + 10000;
        b.iter(|| {
            Primes::new()
                .skip_while(|x| x <= &from)
                .take_while(|x| x < &to)
                .map(|n| n.to_biguint().unwrap())
                .collect::<Vec<BigUint>>()
        });
    }

    #[bench]
    fn dist_range_medium(b: &mut Bencher) {
        let from = 100000;
        let to = from + 10000;
        b.iter(|| {
            Primes::prime_range(
                from.to_biguint().unwrap(),
                to.to_biguint().unwrap(),
                1.to_biguint().unwrap(),
            )
        });
    }

    #[bench]
    fn dist_range_huge(b: &mut Bencher) {
        let num = b"1467923180967075294885675735323676324541564153049833999514232854190565004830812017605189214532225843264116066716156512318969593182391270344778455946362418431315473690995547662440406403933883702433889640683256385143897124931493130999543489479979982760588036516465704083985278537571062266513783550488204590596533270758336933062471517204351390932512929930039938399855920453507167563630259855360201535752462696373117449205677587173382012710734138423402290605978964689147279941717461016763730458182214831495000247921302462425413770606967457598565961362227488304184115780694889150848788831156212021631505646285419187";
        b.iter(|| {
            Primes::prime_range(
                BigUint::parse_bytes(num, 10).unwrap(),
                BigUint::parse_bytes(num, 10).unwrap() + 100.to_biguint().unwrap(),
                1.to_biguint().unwrap(),
            )
        });
    }
}
