use methods::{METHOD_NAME_ELF, METHOD_NAME_ID};
use risc0_zkvm::{
    default_prover,
    ExecutorEnv,
};

fn main() {
    /*
    use std::fs::File;
    use std::io::Write;
    use rand_chacha::rand_core::SeedableRng;
    use ttfhe::ggsw::{compute_bsk};
    use ttfhe::glwe::{keygen, SecretKey};
    use ttfhe::lwe::{lwe_keygen, LweCiphertext};
    use ttfhe::utils::encode;
    use ttfhe::glwe::GlweCiphertext;

    let mut prng = rand_chacha::ChaChaRng::seed_from_u64(123456u64);
    let sk1 = lwe_keygen(&mut prng);
    let sk2 = keygen(&mut prng);
    let bsk = compute_bsk(&mut prng, &sk1, &sk2);
    let c = LweCiphertext::encrypt(&mut prng,encode(2), &sk1).modswitch();

    let buf = unsafe { std::mem::transmute::<&bool, &[u8; 1024]>(&sk1[0]) };
    let mut f = File::create("./sk1").unwrap();
    f.write(buf).unwrap();

    let buf = unsafe { std::mem::transmute::<&SecretKey, &[u8; 8192]>(&sk2) };
    let mut f = File::create("./sk2").unwrap();
    f.write(buf).unwrap();

    let buf = unsafe { std::mem::transmute::<&u64, &[u8; 1048576]>(&bsk[0].z_m_gt[0].mask[0].coefs[0]) };
    let mut f = File::create("./bsk").unwrap();
    f.write(buf).unwrap();

    let buf = unsafe { std::mem::transmute::<&LweCiphertext, &[u8; 8200]>(&c) };
    let mut f = File::create("./c").unwrap();
    f.write(buf).unwrap();

    return;
    */

    let start_time = std::time::Instant::now();

    let env = ExecutorEnv::builder()
        .build()
        .unwrap();

    let prover = default_prover();

    let receipt = prover.prove_elf(env, METHOD_NAME_ELF).unwrap();
    receipt.verify(METHOD_NAME_ID).unwrap();

    println!("Time: {}", start_time.elapsed().as_secs_f64());
}
