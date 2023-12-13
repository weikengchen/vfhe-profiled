use crate::poly::ShortResiduePoly;
use crate::utils::round_value;
use crate::{glwe::GlweCiphertext, k, ELL, N};
use crate::{glwe::SecretKey, lwe::LweSecretKey};
use rand::{CryptoRng, RngCore};

pub type BootstrappingKey = Vec<GgswCiphertext>;

#[derive(Default, Clone, Copy)]
pub struct GgswCiphertext {
    pub z_m_gt: [GlweCiphertext; (k + 1) * ELL],
}

impl GgswCiphertext {
    pub fn encrypt<R: RngCore + CryptoRng>(prng: &mut R, msg: u8, sk: &SecretKey) -> Self {
        // initialize Z
        let mut z_m_gt = [GlweCiphertext::default(); (k + 1) * ELL];

        for i in 0..(k + 1) * ELL {
            z_m_gt[i] = GlweCiphertext::encrypt(prng, 0, sk);
        }

        // m * g, g being [q/B, ..., q/B^l]
        let mut mg = [0u64; ELL];
        mg[0] = (msg as u64) << 56;
        mg[1] = (msg as u64) << 48;

        // add m * G^t to Z
        for i in 0..z_m_gt.len() {
            if i < k * ELL {
                for j in 0..z_m_gt[i].mask.len() {
                    z_m_gt[i].mask[j].add_constant_assign(mg[i % ELL]);
                }
            } else {
                z_m_gt[i].body.add_constant_assign(mg[i % ELL]);
            }
        }

        GgswCiphertext { z_m_gt }
    }

    // The last `GlweCiphertext` of `z_m_gt` is an encryption of msg * q/B^l
    pub fn decrypt(self, sk: &SecretKey) -> u8 {
        ((((&self.z_m_gt[self.z_m_gt.len() - 1].decrypt(sk) >> 47) + 1) >> 1) % 16) as u8
    }

    /// Performs a product (GGSW x GLWE) -> GLWE.
    pub fn external_product(&self, ct: &GlweCiphertext) -> GlweCiphertext {
        let g_inverse_ct = apply_g_inverse(ct);

        let mut res = GlweCiphertext::default();
        for i in 0..(k + 1) * ELL {
            for j in 0..k {
                res.mask[j].add_assign(&g_inverse_ct[i].mul(&self.z_m_gt[i].mask[j]));
            }
            res.body
                .add_assign(&g_inverse_ct[i].mul(&self.z_m_gt[i].body));
        }
        res
    }
}

// impl Default for GgswCiphertext {
//     fn default() -> Self {
//         GgswCiphertext {
//             z_m_gt: Default::default(),
//         }
//     }
// }

/// Decomposition of a GLWE ciphertext.
pub fn apply_g_inverse(ct: &GlweCiphertext) -> Vec<ShortResiduePoly> {
    let mut res: [ShortResiduePoly; (k + 1) * ELL] = Default::default();

    for i in 0..N {
        // mask decomposition
        for j in 0..k {
            let (nu_2, nu_1) = decomposition_8_2(ct.mask[j].coefs[i]);
            res[j * ELL].coefs[i] = nu_1 as i32;
            res[j * ELL + 1].coefs[i] = nu_2 as i32;
        }

        // body decomposition
        let (nu_2, nu_1) = decomposition_8_2(ct.body.coefs[i]);
        res[(k + 1) * ELL - 2].coefs[i] = nu_1 as i32;
        res[(k + 1) * ELL - 1].coefs[i] = nu_2 as i32;
    }
    res.to_vec()
}

/// Approximate decomposition with lg(B) = 8 and ell = 2.
/// Takes a polynomial coefficient in Z_{2^64} and decomposes its 16 MSBs in two signed 8-bit integers.
pub fn decomposition_8_2(val: u64) -> (i8, i8) {
    let rounded_val = round_value(val);
    if rounded_val & 128 == 128 {
        (rounded_val as i8, ((rounded_val >> 8) + 1) as i8)
    } else {
        (rounded_val as i8, (rounded_val >> 8) as i8)
    }
}

/// Ciphertext multiplexer. If `ctb` is an encryption of `1`, return `ct1`. Else, return `ct2`.
pub fn cmux(ctb: &GgswCiphertext, ct1: &GlweCiphertext, ct2: &GlweCiphertext) -> GlweCiphertext {
    let mut res = ct2.sub(ct1);
    res = ctb.external_product(&res);
    res = res.add(ct1);
    res
}

/// Encrypts the bits of `s` under `sk`
pub fn compute_bsk<R: CryptoRng + RngCore>(
    prng: &mut R,
    s: &LweSecretKey,
    sk: &SecretKey,
) -> BootstrappingKey {
    let mut bsk = Vec::<GgswCiphertext>::new();

    for i in 0..N {
        bsk.push(GgswCiphertext::encrypt(prng, s[i].try_into().unwrap(), sk));
    }

    bsk
}

#[cfg(test)]
mod tests {
    use crate::ggsw::{cmux, GgswCiphertext};
    use crate::glwe::{keygen, GlweCiphertext};
    use crate::utils::{decode, encode};
    use rand::{thread_rng, Rng};

    #[test]
    fn test_keygen_enc_dec() {
        let prng = &mut thread_rng();

        let sk = keygen(prng);
        for _ in 0..100 {
            let msg = thread_rng().gen_range(0..16);
            let ct = GgswCiphertext::encrypt(prng, msg, &sk);
            let pt = ct.decrypt(&sk);
            assert_eq!(msg, pt as u8);
        }
    }

    #[test]
    fn test_external_product() {
        let prng = &mut thread_rng();

        let sk = keygen(prng);
        for _ in 0..100 {
            let msg1 = thread_rng().gen_range(0..16);
            let msg2 = thread_rng().gen_range(0..16);
            let ct1 = GgswCiphertext::encrypt(prng, msg1, &sk);
            let ct2 = GlweCiphertext::encrypt(prng, encode(msg2), &sk);
            let res = ct1.external_product(&ct2);
            let pt = decode(res.decrypt(&sk));
            let expected: u8 = msg1 * msg2 % 16;
            assert_eq!(expected, pt);
        }
    }

    #[test]
    fn test_cmux() {
        let prng = &mut thread_rng();

        for _ in 0..100 {
            let sk = keygen(prng);
            let msg1 = thread_rng().gen_range(0..16);
            let msg2 = thread_rng().gen_range(0..16);
            let b = thread_rng().gen_range(0..2);

            let ct1 = GlweCiphertext::encrypt(prng, encode(msg1), &sk);
            let ct2 = GlweCiphertext::encrypt(prng, encode(msg2), &sk);
            let ctb = GgswCiphertext::encrypt(prng, b, &sk);

            let res = cmux(&ctb, &ct1, &ct2);

            let pt = decode(res.decrypt(&sk));
            assert_eq!(pt, (1 - b) * msg1 + b * msg2);
        }
    }

    #[test]
    fn test_cmux_trivial() {
        let prng = &mut thread_rng();

        for _ in 0..100 {
            let sk = keygen(prng);
            let msg1 = thread_rng().gen_range(0..16);
            let msg2 = thread_rng().gen_range(0..16);
            let b = thread_rng().gen_range(0..2);

            let ct1 = GlweCiphertext::trivial_encrypt(encode(msg1));
            let ct2 = GlweCiphertext::trivial_encrypt(encode(msg2));
            let ctb = GgswCiphertext::encrypt(prng, b, &sk);

            let res = cmux(&ctb, &ct1, &ct2);

            let pt = decode(res.decrypt(&sk));

            assert_eq!(pt, (1 - b) * msg1 + b * msg2);
        }
    }
}
