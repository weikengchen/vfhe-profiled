#![no_main]
#![feature(new_uninit)]

use risc0_zkvm::guest::env;
use ttfhe::{N,
    ggsw::GgswCiphertext,
    glwe::SecretKey,
    lwe::LweSecretKey
};
risc0_zkvm::guest::entry!(main);

static SK1_BYTES: &[u8] = include_bytes!("./sk1");
static SK2_BYTES: &[u8; 8192] = include_bytes!("./sk2");
static BSK_BYTES: &[u8] = include_bytes!("./bsk");

pub fn main() {
    let sk1 = unsafe {
        std::mem::transmute::<&u8, &LweSecretKey>(&SK1_BYTES[0])
    };
    eprintln!("{}", sk1[0]);
    eprintln!("{}", env::get_cycle_count());

    let sk2 = unsafe {
        std::mem::transmute::<&u8, &SecretKey>(&SK2_BYTES[0])
    };
    eprintln!("{}", sk2.polys[0].coefs[0]);
    eprintln!("{}", env::get_cycle_count());

    let bsk = unsafe {
        std::mem::transmute::<&u8, &[GgswCiphertext; N]>(&BSK_BYTES[0])
    };
    eprintln!("{}", bsk[0].z_m_gt[0].body.coefs[0]);
    eprintln!("{}", env::get_cycle_count());
}
