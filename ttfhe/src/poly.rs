use std::mem::MaybeUninit;
use crate::N;
use rand::{Rng, CryptoRng, RngCore};
use crate::karatsuba::negacyclic_asymmetric_karatsuba_1024;

/// Represents an element of Z_{q}\[X\]/(X^N + 1) with implicit q = 2^64.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ResiduePoly {
    pub coefs: [u64; N],
}

impl ResiduePoly {
    pub fn new() -> Self {
        ResiduePoly {
            coefs: [0u64; N],
        }
    }

    pub fn add(&self, rhs: &ResiduePoly) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.coefs[i] = self.coefs[i].wrapping_add(rhs.coefs[i]);
        }
        res
    }

    pub fn add_assign(&mut self, rhs: &ResiduePoly) {
        for i in 0..N {
            self.coefs[i] = self.coefs[i].wrapping_add(rhs.coefs[i]);
        }
    }

    pub fn add_constant(&self, constant: u64) -> Self {
        let mut res: ResiduePoly = self.clone();
        res.coefs[0] = res.coefs[0].wrapping_add(constant);
        res
    }

    pub fn add_constant_assign(&mut self, constant: u64) {
        self.coefs[0] = self.coefs[0].wrapping_add(constant);
    }

    pub fn sub(&self, rhs: &ResiduePoly) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.coefs[i] = self.coefs[i].wrapping_sub(rhs.coefs[i]);
        }
        res
    }

    // TODO: use NTT for better performances
    pub fn mul(&self, rhs: &ResiduePoly) -> Self {
        let mut coefs = [0u64; N];
        for i in 0..N {
            let mut coef = 0u64;
            for j in 0..i + 1 {
                coef = coef.wrapping_add(self.coefs[j].wrapping_mul(rhs.coefs[i - j]));
            }
            for j in i + 1..N {
                coef = coef.wrapping_sub(self.coefs[j].wrapping_mul(rhs.coefs[N - j + i]));
            }
            coefs[i] = coef;
        }
        ResiduePoly { coefs }
    }

    /// Generates a residue polynomial with random coefficients in \[0..2^64)
    pub fn get_random<R: RngCore + CryptoRng>(prng: &mut R) -> Self {
        let mut coefs = [0u64; N];
        for i in 0..N {
            coefs[i] = prng.gen::<u64>();
        }

        Self { coefs }
    }

    /// Generates a residue polynomial with random coefficients in \[0..1\]
    pub fn get_random_bin<R: CryptoRng+RngCore>(prng: &mut R) -> Self {
        let mut coefs = [0u64; N];
        for i in 0..N {
            coefs[i] = prng.gen_range(0..=1);
        }

        Self { coefs }
    }

    /// Multiplies the residue polynomial by X^{exponent} = X^{2N + exponent}.
    /// `exponent` is assumed to be reduced modulo 2N.
    pub fn multiply_by_monomial(&self, exponent: usize) -> Self {
        let mut rotated_coefs = [0u64; N];

        let reverse = exponent >= N;
        let exponent = exponent % N;

        for i in 0..N {
            rotated_coefs[i] = {
                if i < exponent {
                    if reverse {
                        self.coefs[i + N - exponent]
                    } else {
                        self.coefs[i + N - exponent].wrapping_neg()
                    }
                } else if reverse {
                    self.coefs[i - exponent].wrapping_neg()
                } else {
                    self.coefs[i - exponent]
                }
            }
        }

        ResiduePoly {
            coefs: rotated_coefs,
        }
    }
}

impl Default for ResiduePoly {
    fn default() -> Self {
        ResiduePoly {
            coefs: [0u64; N],
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ShortResiduePoly {
    pub coefs: [i32; N],
}

impl ShortResiduePoly {
    pub fn mul(&self, rhs: &ResiduePoly) -> ResiduePoly {
        let mut coefs = MaybeUninit::<[u64; N]>::uninit();
        unsafe {
            negacyclic_asymmetric_karatsuba_1024(&mut (*coefs.as_mut_ptr()), &self.coefs, &rhs.coefs);
            ResiduePoly { coefs: coefs.assume_init() }
        }
    }
}

impl Default for ShortResiduePoly {
    fn default() -> Self {
        ShortResiduePoly {
            coefs: [0i32; N],
        }
    }
}


#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::{poly::ResiduePoly, N};

    #[test]
    /// Tests that the monomial multiplication is coherent with monomial multiplication.
    fn test_monomial_mult() {
        let prng = &mut thread_rng();

        for _ in 0..1000 {
            let mut monomial_coefs = [0u64; N];
            let monomial_non_null_term = prng.gen_range(0..2 * N);

            if monomial_non_null_term < 1024 {
                monomial_coefs[monomial_non_null_term] = 1;
            } else {
                monomial_coefs[monomial_non_null_term % 1024] = 1u64.wrapping_neg();
            }

            let monomial = ResiduePoly {
                coefs: monomial_coefs,
            };

            let polynomial = ResiduePoly::get_random(prng);

            let res_mul = polynomial.mul(&monomial);
            let res_monomial_mul = polynomial.multiply_by_monomial(monomial_non_null_term);

            assert_eq!(res_mul.coefs, res_monomial_mul.coefs);
        }
    }
}
