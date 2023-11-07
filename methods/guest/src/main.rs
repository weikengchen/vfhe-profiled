#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
// #![no_std]  // std support is experimental

use std::fs::File;
use std::io::Write;
use std::mem::MaybeUninit;
use risc0_zkvm::guest::env;
use ttfhe::{
    ggsw::BootstrappingKey,
    glwe::GlweCiphertext,
    lwe::{KeySwitchingKey},
};
use ttfhe::{LWE_DIM, N,
    ggsw::{GgswCiphertext, compute_bsk},
    glwe::{SecretKey, keygen},
    poly::ResiduePoly,
    lwe::{compute_ksk, lwe_keygen, LweSecretKey, LweCiphertext},
    utils::{decode_bootstrapped, encode},
};
use rand_chacha::rand_core::SeedableRng;
risc0_zkvm::guest::entry!(main);

static SK1_BYTES: &[u8] = include_bytes!("./sk1");
static SK2_BYTES: &[u8; 8192] = include_bytes!("./sk2");

static BSK_BYTES: &[u8] = include_bytes!("./bsk");

pub fn main() {
    let mut sk1 = [false; 1024];
    for i in 0..LWE_DIM {
        sk1[i] = SK1_BYTES[i] != 0;
    }
    eprintln!("{}", sk1[0]);
    eprintln!("{}", env::get_cycle_count());

    let sk2 = {
        let mut coefs = [0u64; 1024];
        coefs.copy_from_slice( unsafe { std::mem::transmute::<&[u8; 8192], &[u64; 1024]>(SK2_BYTES) });
        let poly = ResiduePoly {
            coefs,
        };
        SecretKey{
            polys: [poly]
        }
    };
    eprintln!("{}", sk2.polys[0].coefs[0]);
    eprintln!("{}", env::get_cycle_count());

    let mut bsk: [GgswCiphertext; N] = unsafe {MaybeUninit::<[GgswCiphertext; N]>::uninit().assume_init()};

    for i in 0..N {
        for j in 0..4usize {
            let dst_ptr = &mut bsk[i].z_m_gt[j].mask[0].coefs[0] as *mut u64;
            let src_ptr = unsafe {
                (std::mem::transmute::<&u8, &u64>(&BSK_BYTES[(16384 * (4 * i + j) as usize)])) as *const u64
            };

            unsafe {
                std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, 1024);
            }

            let dst_ptr = &mut bsk[i].z_m_gt[j].body.coefs[0] as *mut u64;
            let src_ptr = unsafe {
                (std::mem::transmute::<&u8, &u64>(&BSK_BYTES[((16384 * (4 * i + j)  + 8192)as usize)])) as *const u64
            };

            unsafe {
                std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, 1024);
            }
        }
    }
    eprintln!("{}", bsk[0].z_m_gt[0].mask[0].coefs[0]);
    eprintln!("{}", env::get_cycle_count());
}
