use crate::utils::round_value;
use crate::LWE_DIM;
use rand::{CryptoRng, Rng, RngCore};
use rand_distr::{Distribution, Normal};

#[derive(Clone)]
pub struct LweCiphertext {
    pub mask: [u64; LWE_DIM],
    pub body: u64,
}

pub type LweSecretKey = [bool; LWE_DIM];
pub type KeySwitchingKey = Vec<LweCiphertext>;

impl LweCiphertext {
    pub fn encrypt<R: CryptoRng + RngCore>(
        prng: &mut R,
        mu: u64,
        sk: &LweSecretKey,
    ) -> LweCiphertext {
        let sigma = f64::powf(2.0, 49.0);
        let normal = Normal::new(0.0, sigma).unwrap();

        let e = normal.sample(prng).round() as i64;
        let mu_star = mu.wrapping_add_signed(e);

        let mut mask = [0u64; LWE_DIM];

        for i in 0..LWE_DIM {
            mask[i] = prng.gen::<u64>();
        }

        let mut body = 0u64;
        for i in 0..LWE_DIM {
            if sk[i] {
                body = body.wrapping_add(mask[i]);
            }
        }

        body = body.wrapping_add(mu_star);

        LweCiphertext { mask, body }
    }

    pub fn decrypt(self, sk: &LweSecretKey) -> u64 {
        let mut body: u64 = 0u64;
        for i in 0..LWE_DIM {
            if sk[i] {
                body = body.wrapping_add(self.mask[i]);
            }
        }

        self.body.wrapping_sub(body) // mu_star
    }

    pub fn decrypt_modswitched(self, sk: &LweSecretKey) -> u64 {
        let mut dot_prod = 0u64;
        for i in 0..LWE_DIM {
            if sk[i] {
                dot_prod = (dot_prod + self.mask[i]) % (2 * LWE_DIM as u64);
            }
        }

        self.body.wrapping_sub(dot_prod) % (2 * LWE_DIM as u64) // mu_star
    }

    pub fn add(self, rhs: Self) -> Self {
        let mut mask = [0u64; LWE_DIM];

        for i in 0..LWE_DIM {
            mask[i] = self.mask[i].wrapping_add(rhs.mask[i]);
        }

        let body = self.body.wrapping_add(rhs.body);

        LweCiphertext { mask, body }
    }

    pub fn sub(self, rhs: &Self) -> Self {
        let mut mask = [0u64; LWE_DIM];

        for i in 0..LWE_DIM {
            mask[i] = self.mask[i].wrapping_sub(rhs.mask[i]);
        }

        let body = self.body.wrapping_sub(rhs.body);

        LweCiphertext { mask, body }
    }

    pub fn multiply_constant_assign(&mut self, constant: u64) -> &mut Self {
        let mut mask = [0u64; LWE_DIM];

        for i in 0..LWE_DIM {
            mask[i] = self.mask[i].wrapping_mul(constant);
        }

        self.body = self.body.wrapping_mul(constant);

        self
    }

    /// Switch from modulus 2^64 to 2N, with 2N = 2^11.
    pub fn modswitch(&self) -> Self {
        let mut mask = [0u64; LWE_DIM];

        for i in 0..LWE_DIM {
            mask[i] = ((self.mask[i] >> 52) + 1) >> 1;
        }

        let body = ((self.body >> 52) + 1) >> 1;

        LweCiphertext { mask, body }
    }
}

/// Approximate decomposition with lg(B) = 4 and ell = 4.
/// Takes a polynomial coefficient in Z_{2^64} and decomposes its 16 MSBs in 4 integers in `[-8, 7] as u64`.
pub fn decomposition_4_4(val: u64) -> [u64; 4] {
    let mut ret = [0u64; 4];
    let rounded_val = round_value(val);

    let mut carry = 0u64;
    for i in 0..4 {
        let mut res = ((rounded_val >> (4 * i)) & 0x0F) + carry;

        let carry_bit = res & 8;

        res = res.wrapping_sub(carry_bit << 1);
        ret[i] = res;

        carry = carry_bit >> 3;
    }

    ret
}

impl Default for LweCiphertext {
    fn default() -> Self {
        LweCiphertext {
            mask: [0u64; LWE_DIM],
            body: 0u64,
        }
    }
}

pub fn lwe_keygen<R: CryptoRng + RngCore>(prng: &mut R) -> LweSecretKey {
    let mut sk = [false; LWE_DIM];
    for i in 0..LWE_DIM {
        sk[i] = prng.gen_bool(0.5);
    }

    sk
}

/// Encrypts `sk1` under `sk2`.
// TODO: generalize for k > 1
pub fn compute_ksk<R: CryptoRng + RngCore>(
    prng: &mut R,
    sk1: &LweSecretKey,
    sk2: &LweSecretKey,
) -> KeySwitchingKey {
    let mut ksk = vec![];

    for bit in sk1.iter().take(LWE_DIM) {
        // 4 layers in the decomposition for the KSK
        for j in 0..4 {
            let mu = (*bit as u64) << (48 + (4 * j)); // lg(B) = 4
            ksk.push(LweCiphertext::encrypt(prng, mu, sk2));
        }
    }
    ksk
}

#[cfg(test)]
mod tests {
    use crate::lwe::{lwe_keygen, LweCiphertext};
    use crate::utils::{decode, decode_modswitched, encode};
    use rand::{thread_rng, Rng};

    #[test]
    fn test_keygen_enc_dec() {
        let prng = &mut thread_rng();

        let sk = lwe_keygen(prng);
        for _ in 0..100 {
            let msg = thread_rng().gen_range(0..16);
            let ct = LweCiphertext::encrypt(prng, encode(msg), &sk);
            let pt = decode(ct.decrypt(&sk));
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn test_add() {
        let prng = &mut thread_rng();

        let sk = lwe_keygen(prng);
        for _ in 0..100 {
            let msg1 = thread_rng().gen_range(0..16);
            let msg2 = thread_rng().gen_range(0..16);
            let ct1 = LweCiphertext::encrypt(prng, encode(msg1), &sk);
            let ct2 = LweCiphertext::encrypt(prng, encode(msg2), &sk);
            let res = ct1.add(ct2);
            let pt = decode(res.decrypt(&sk));
            assert_eq!(pt, (msg1 + msg2) % 16);
        }
    }

    #[test]
    fn test_sub() {
        let prng = &mut thread_rng();

        let sk = lwe_keygen(prng);
        for _ in 0..100 {
            let msg1 = thread_rng().gen_range(0..16);
            let msg2 = thread_rng().gen_range(0..16);
            let ct1 = LweCiphertext::encrypt(prng, encode(msg1), &sk);
            let ct2 = LweCiphertext::encrypt(prng, encode(msg2), &sk);
            let res = ct1.sub(&ct2);
            let pt = decode(res.decrypt(&sk));
            assert_eq!(pt, (msg1.wrapping_sub(msg2)) % 16);
        }
    }

    #[test]
    fn test_modswitch() {
        let prng = &mut thread_rng();

        for _ in 0..100 {
            let sk = lwe_keygen(prng);
            let msg = thread_rng().gen_range(0..16);
            let ct = LweCiphertext::encrypt(prng, encode(msg), &sk);
            let modswitched = ct.modswitch();
            let pt = decode_modswitched(modswitched.decrypt_modswitched(&sk));
            assert_eq!(pt, msg);
        }
    }
}
