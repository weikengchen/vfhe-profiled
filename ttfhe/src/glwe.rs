use rand::{CryptoRng, RngCore};
use crate::ggsw::{cmux, BootstrappingKey};
use crate::lwe::{LweCiphertext, LweSecretKey};
use crate::utils::encode;
use crate::P;
use crate::{k, poly::ResiduePoly, LWE_DIM, N};
use rand_distr::{Distribution, Normal};

#[derive(Clone, Copy, Default)]
pub struct GlweCiphertext {
    pub mask: [ResiduePoly; k],
    pub body: ResiduePoly,
}

/// Set of `k` polynomials in {0, 1}\[X\]/(X^N + 1).
#[derive(Clone)]
#[repr(C)]
pub struct SecretKey {
    pub polys: [ResiduePoly; k]
}

impl GlweCiphertext {
    pub fn encrypt<R: RngCore+CryptoRng>(prng: &mut R, mu: u64, sk: &SecretKey) -> GlweCiphertext {
        let sigma = f64::powf(2.0, 39.0);
        let normal = Normal::new(0.0, sigma).unwrap();

        let e = normal.sample(prng).round() as i64;
        let mu_star = mu.wrapping_add_signed(e);

        let mut mask = [ResiduePoly::default(); k];
        for i in 0..k{
            mask[i] = ResiduePoly::get_random(prng);
        }

        let mut body = ResiduePoly::default();
        for i in 0..k {
            body.add_assign(&mask[i].mul(&sk.polys[i]));
        }

        body.add_constant_assign(mu_star as u64);

        GlweCiphertext { mask, body }
    }

    pub fn decrypt(&self, sk: &SecretKey) -> u64 {
        let mut body = ResiduePoly::default();
        for i in 0..k {
            body.add_assign(&self.mask[i].mul(&sk.polys[i]));
        }

        let mu_star = self.body.sub(&body);
        mu_star.coefs[0].clone()
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut res = GlweCiphertext::default();
        for i in 0..k {
            res.mask[i] = self.mask[i].add(&rhs.mask[i]);
        }
        res.body = self.body.add(&rhs.body);
        res
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let mut res = GlweCiphertext::default();
        for i in 0..k {
            res.mask[i] = self.mask[i].sub(&rhs.mask[i]);
        }
        res.body = self.body.sub(&rhs.body);
        res
    }

    /// Converts a GLWE ciphertext into a LWE ciphertext.
    // TODO: generalize for k > 1
    pub fn sample_extract(&self) -> LweCiphertext {
        let mut mask = [0u64; LWE_DIM];
        mask[0] = self.mask[0].coefs[0];
        for i in 1..LWE_DIM {
            mask[i] = self.mask[0].coefs[LWE_DIM - i].wrapping_neg();
        }

        let body = self.body.coefs[0];

        LweCiphertext {
            mask: mask,
            body,
        }
    }

    /// Trivially encrypts `mu`.
    pub fn trivial_encrypt(mu: u64) -> Self {
        let mut res = Self::default();
        res.body.coefs[0] = mu;
        res
    }

    /// Performs the blind rotation of `self`.
    // `self` is assumed to be a trivial encryption
    // `c` is a modswitched LWE ciphertext (modulus = 2N)
    pub fn blind_rotate(&self, c: LweCiphertext, bsk: &BootstrappingKey) -> Self {
        let mut c_prime = self.clone();

        c_prime.rotate_trivial((2 * N as u64) - c.body);
        for i in 0..N {
            c_prime = cmux(&bsk[i], &c_prime, &c_prime.rotate(c.mask[i]));
        }

        c_prime
    }

    /// Multiplies by the monomial `X^exponent` the body of `self`.
    /// `self` is assumed to be a trivial encryption.
    pub fn rotate_trivial(&mut self, exponent: u64) {
        self.body = self.body.multiply_by_monomial(exponent as usize);
    }

    /// Multiplies by the monomial `X^exponent` every component of `self`.
    pub fn rotate(&self, exponent: u64) -> Self {
        let mut res = Self::default();
        for i in 0..k {
            res.mask[i] = self.mask[i].multiply_by_monomial(exponent as usize);
        }

        res.body = self.body.multiply_by_monomial(exponent as usize);

        res
    }

    /// Trivially encrypts the LUT polynomial.
    pub fn trivial_encrypt_lut_poly() -> Self {
        // TODO: use iterator
        let mut lut_coefs = [0u64; N];

        for i in 0..N {
            lut_coefs[(i.wrapping_sub(64)) % N] = encode(((P * i) / (2 * N)).try_into().unwrap());
        }

        Self {
            body: ResiduePoly {
                coefs: lut_coefs,
            },
            ..Default::default()
        }
    }
}

impl SecretKey {
    /// Converts a GLWE secret key into a LWE secret key.
    // TODO: generalize for k > 1
    pub fn recode(&self) -> LweSecretKey {
        let mut res = [false; LWE_DIM];
        for (i, b) in self.polys[0].coefs.iter().enumerate() {
            res[i] = (*b) != 0;
        }
        res
    }
}

pub fn keygen<R: RngCore+CryptoRng>(prng: &mut R) -> SecretKey {
    let mut polys = [ResiduePoly::default(); k];
    for i in 0.. k{
        polys[i] = ResiduePoly::get_random_bin(prng);
    }

    SecretKey { polys }
}

#[cfg(test)]
mod tests {
    use crate::ggsw::compute_bsk;
    use crate::glwe::{keygen, GlweCiphertext};
    use crate::lwe::{LweCiphertext, LweSecretKey};
    use crate::utils::{decode, decode_bootstrapped, encode};
    use rand::{thread_rng, Rng};

    #[test]
    // #[ignore]
    fn test_blind_rotation() {
        let prng = &mut thread_rng();

        let sk1 = keygen(prng).recode();
        let sk2 = keygen(prng);
        let bsk = compute_bsk(prng,&sk1, &sk2); // list of encryptions under `sk2` of the bits of `sk1`.

        let lut = GlweCiphertext::trivial_encrypt_lut_poly();

        for _ in 0..16 {
            let msg = prng.gen_range(0..8);

            // TODO: keyswitch `c` to a smaller dimension
            let c = LweCiphertext::encrypt(prng,encode(msg), &sk1).modswitch(); // "noisy" ciphertext that will be bootstrapped

            let blind_rotated_lut = lut.blind_rotate(c, &bsk); // should return a GLWE encryption of X^{- \tilde{\mu}^*} * v(X) which should be equal to a polynomial with constant term \mu.

            let res = blind_rotated_lut.sample_extract().decrypt(&sk2.recode());
            let pt = decode_bootstrapped(res);

            assert_eq!(msg, pt)
        }
    }

    #[test]
    fn test_keygen_enc_dec() {
        let prng = &mut thread_rng();

        let sk = keygen(prng);
        for _ in 0..100 {
            let msg = prng.gen_range(0..16);
            let ct = GlweCiphertext::encrypt(prng,encode(msg), &sk);
            let pt = decode(ct.decrypt(&sk));
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn test_add() {
        let prng = &mut thread_rng();

        let sk = keygen(prng);
        for _ in 0..100 {
            let msg1 = prng.gen_range(0..16);
            let msg2 = prng.gen_range(0..16);
            let ct1 = GlweCiphertext::encrypt(prng,encode(msg1), &sk);
            let ct2 = GlweCiphertext::encrypt(prng,encode(msg2), &sk);
            let res = ct1.add(&ct2);
            let pt = decode(res.decrypt(&sk));
            assert_eq!(pt, (msg1 + msg2) % 16);
        }
    }

    #[test]
    fn test_sub() {
        let prng = &mut thread_rng();

        let sk = keygen(prng);
        for _ in 0..100 {
            let msg1 = prng.gen_range(0..16);
            let msg2 = prng.gen_range(0..16);
            let ct1 = GlweCiphertext::encrypt(prng,encode(msg1), &sk);
            let ct2 = GlweCiphertext::encrypt(prng,encode(msg2), &sk);
            let res = ct1.sub(&ct2);
            let pt = decode(res.decrypt(&sk));
            assert_eq!(pt, (msg1.wrapping_sub(msg2)) % 16);
        }
    }

    #[test]
    fn test_sample_extract() {
        let prng = &mut thread_rng();

        let sk = keygen(prng);
        let msg = prng.gen_range(0..16);
        let ct = GlweCiphertext::encrypt(prng,encode(msg), &sk);

        let sample_extracted: LweCiphertext = ct.sample_extract();
        let recoded_sk: LweSecretKey = sk.recode();

        let pt = decode(sample_extracted.decrypt(&recoded_sk));
        assert_eq!(pt, msg)
    }
}
