use super::asymmetric_karatsuba_512;
use core::mem::transmute;
use core::mem::MaybeUninit;
macro_rules! negacyclic_asymmetric_karatsuba {
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
        let left =
            unsafe { transmute::<&mut u64, &mut [u64; 2 * $a - 1]>(&mut (*pad.as_mut_ptr())[0]) };
        let right = unsafe { transmute::<&mut u64, &mut [u64; 2 * $a - 1]>(&mut $res[0]) };
        unsafe {
            $name(&mut *mid.as_mut_ptr(), &a_plus_b, &c_plus_d);
        }

        // after the mid, a_plus_b and c_plus_d are no longer needed
        $name(left, &a, &c);

        $name(right, &b, &d);

        unsafe {
            for i in 0..(2 * $a - 1) {
                (*mid.as_mut_ptr())[i] = (*mid.as_ptr())[i]
                    .wrapping_sub(left[i])
                    .wrapping_sub(right[i]);
                right[i] = right[i].wrapping_sub(left[i]);
            }
        }

        unsafe {
            for i in 0..($a - 1) {
                $res[i + $a] = $res[i + $a].wrapping_add((*mid.as_ptr())[i]);
            }
            $res[2 * $a - 1] = (*mid.as_ptr())[$a - 1];
            for i in $a..(2 * $a - 1) {
                $res[i - $a] = $res[i - $a].wrapping_sub((*mid.as_ptr())[i]);
            }
        }
    };
}

#[inline]
pub fn negacyclic_asymmetric_karatsuba_1024(
    res: &mut [u64; 1024],
    lhs: &[i32; 1024],
    rhs: &[u64; 1024],
) {
    negacyclic_asymmetric_karatsuba!(512, lhs, rhs, res, asymmetric_karatsuba_512);
}

#[cfg(test)]
mod test {
    use super::negacyclic_asymmetric_karatsuba_1024;
    use rand::Rng;
    use rand_chacha::rand_core::{RngCore, SeedableRng};

    #[test]
    fn test_negacyclic_karatsuba() {
        let mut prng = rand_chacha::ChaCha20Rng::seed_from_u64(1u64);

        let mut res = [0u64; 1024];
        let mut lhs = [0i32; 1024];
        let mut rhs = [0u64; 1024];

        for i in 0..1024 {
            lhs[i] = (prng.next_u32() % 256) as i32;
            if prng.gen_bool(0.5) {
                lhs[i] = -lhs[i];
            }
            rhs[i] = prng.next_u64();
        }

        let mut answer = [0u64; 1024];

        for i in 0..1024 {
            for j in 0..i + 1 {
                answer[i] = answer[i].wrapping_add(rhs[i - j].wrapping_mul(lhs[j] as u64));
            }
            for j in i + 1..1024 {
                answer[i] = answer[i].wrapping_sub(rhs[1024 - j + i].wrapping_mul(lhs[j] as u64));
            }
        }
        negacyclic_asymmetric_karatsuba_1024(&mut res, &lhs, &rhs);
        for i in 0..1024 {
            assert_eq!(answer[i], res[i]);
        }
    }
}
