use core::mem::{transmute, MaybeUninit};

macro_rules! asymmetric_karatsuba {
    ($a:expr, $lhs: ident, $rhs: ident, $res: ident, $name: ident) => {
        let a = unsafe { transmute::<&i32, &[i32; $a]>(&$lhs[$a]) };
        let b = unsafe { transmute::<&i32, &[i32; $a]>(&$lhs[0]) };
        let c = unsafe { transmute::<&u64, &[u64; $a]>(&$rhs[$a]) };
        let d = unsafe { transmute::<&u64, &[u64; $a]>(&$rhs[0]) };

        let mut pad = MaybeUninit::<[u64; 2 * $a]>::uninit();
        let a_plus_b =
            unsafe { transmute::<&mut u64, &mut [i32; $a]>(&mut (*pad.as_mut_ptr())[0]) };
        let c_plus_d =
            unsafe { transmute::<&mut u64, &mut [u64; $a]>(&mut (*pad.as_mut_ptr())[$a]) };

        for i in 0..$a {
            a_plus_b[i] = a[i].wrapping_add(b[i]);
            c_plus_d[i] = c[i].wrapping_add(d[i]);
        }

        let mut mid = MaybeUninit::<[u64; 2 * $a - 1]>::uninit();
        let left = unsafe { transmute::<&mut u64, &mut [u64; 2 * $a - 1]>(&mut $res[2 * $a]) };
        let right = unsafe { transmute::<&mut u64, &mut [u64; 2 * $a - 1]>(&mut $res[0]) };

        unsafe {
            $name(&mut (*mid.as_mut_ptr()), &a_plus_b, &c_plus_d);
        }
        $name(left, &a, &c);
        $name(right, &b, &d);

        unsafe {
            for i in 0..(2 * $a - 1) {
                (*pad.as_mut_ptr())[i] = $res[i].wrapping_add($res[i + 2 * $a]);
            }
        }

        unsafe {
            for i in 0..($a - 1) {
                $res[i + $a] = $res[i + $a]
                    .wrapping_add((*mid.as_ptr())[i])
                    .wrapping_sub((*pad.as_ptr())[i]);
            }
            $res[2 * $a - 1] = (*mid.as_ptr())[$a - 1].wrapping_sub((*pad.as_ptr())[$a - 1]);
            for i in $a..(2 * $a - 1) {
                $res[i + $a] = $res[i + $a]
                    .wrapping_add((*mid.as_ptr())[i])
                    .wrapping_sub((*pad.as_ptr())[i]);
            }
        }
    };
}

#[inline(always)]
pub fn asymmetric_karatsuba_8(res: &mut [u64; 15], lhs: &[i32; 8], rhs: &[u64; 8]) {
    for i in 0..8 {
        for j in 0..8 {
            res[i + j] = rhs[i] * (lhs[i] as u64);
        }
    }
}

#[inline(always)]
pub fn asymmetric_karatsuba_16(res: &mut [u64; 31], lhs: &[i32; 16], rhs: &[u64; 16]) {
    asymmetric_karatsuba!(8, lhs, rhs, res, asymmetric_karatsuba_8);
}

#[inline]
pub fn asymmetric_karatsuba_32(res: &mut [u64; 63], lhs: &[i32; 32], rhs: &[u64; 32]) {
    asymmetric_karatsuba!(16, lhs, rhs, res, asymmetric_karatsuba_16);
}

#[inline]
pub fn asymmetric_karatsuba_64(res: &mut [u64; 127], lhs: &[i32; 64], rhs: &[u64; 64]) {
    asymmetric_karatsuba!(32, lhs, rhs, res, asymmetric_karatsuba_32);
}

#[inline]
pub fn asymmetric_karatsuba_128(res: &mut [u64; 255], lhs: &[i32; 128], rhs: &[u64; 128]) {
    asymmetric_karatsuba!(64, lhs, rhs, res, asymmetric_karatsuba_64);
}

#[inline]
pub fn asymmetric_karatsuba_256(res: &mut [u64; 511], lhs: &[i32; 256], rhs: &[u64; 256]) {
    asymmetric_karatsuba!(128, lhs, rhs, res, asymmetric_karatsuba_128);
}

#[inline]
pub fn asymmetric_karatsuba_512(res: &mut [u64; 1023], lhs: &[i32; 512], rhs: &[u64; 512]) {
    asymmetric_karatsuba!(256, lhs, rhs, res, asymmetric_karatsuba_256);
}

#[cfg(test)]
mod test {
    use super::asymmetric_karatsuba_512;
    use rand::Rng;
    use rand_chacha::rand_core::{RngCore, SeedableRng};

    #[test]
    fn test_asymmetric_karatsuba() {
        let mut prng = rand_chacha::ChaCha20Rng::seed_from_u64(1u64);

        let mut res = [0u64; 1023];
        let mut lhs = [0i32; 512];
        let mut rhs = [0u64; 512];

        for i in 0..512 {
            lhs[i] = (prng.next_u32() % 256) as i32;
            if prng.gen_bool(0.5) {
                lhs[i] = -lhs[i];
            }
            rhs[i] = prng.next_u64();
        }

        let mut answer = [0u64; 1023];
        for i in 0..512 {
            for j in 0..512 {
                answer[i + j] = answer[i + j].wrapping_add(rhs[i].wrapping_mul(lhs[j] as u64));
            }
        }
        asymmetric_karatsuba_512(&mut res, &lhs, &rhs);
        for i in 0..1023 {
            assert_eq!(answer[i], res[i]);
        }
    }
}
