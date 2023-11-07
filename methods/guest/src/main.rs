#![no_main]

use risc0_zkvm::guest::env;
use core::hint::black_box;
use ttfhe::{N,
    ggsw::{cmux, GgswCiphertext},
    glwe::GlweCiphertext,
    lwe::LweCiphertext
};
risc0_zkvm::guest::entry!(main);

static BSK_BYTES: &[u8] = include_bytes!("../../../bsk");
static C_BYTES: &[u8] = include_bytes!("../../../c");

pub fn main() {
    let init_cycle = env::get_cycle_count();

    let bsk = black_box(unsafe {
        std::mem::transmute::<&u8, &[GgswCiphertext; 16]>(&BSK_BYTES[0])
    });

    let c = black_box(unsafe {
        std::mem::transmute::<&u8, &LweCiphertext>(&C_BYTES[0])
    });

    let after_load_cycle = env::get_cycle_count();
    eprintln!("load keys: {} {}", init_cycle, after_load_cycle);

    let lut = black_box(GlweCiphertext::trivial_encrypt_lut_poly());
    let after_lut_cycle = env::get_cycle_count();
    eprintln!("lut: {}", after_lut_cycle);

    let mut c_prime = lut.clone();
    c_prime.rotate_trivial((2 * N as u64) - c.body);

    let after_initial_rotate = env::get_cycle_count();
    eprintln!("trivial rotate: {}", after_initial_rotate);

    for i in 0..1 {
        let rotated = c_prime.rotate(c.mask[i]);
        let after_rotate = env::get_cycle_count();
        eprintln!("rotate: {}", after_rotate);

        c_prime = cmux(&bsk[i], &c_prime, &rotated);
        let after_cmux = env::get_cycle_count();
        eprintln!("cmux: {}", after_cmux);
    }
}
