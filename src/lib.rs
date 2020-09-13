#![feature(test)]
extern crate test;

mod prime;

#[cfg(test)]
mod tests {
    use super::prime::PrimeGenerator;
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
}
