use methods::{METHOD_NAME_ELF, METHOD_NAME_ID};
use risc0_zkvm::{
    default_prover,
    ExecutorEnv,
};

fn main() {
    println!("{:?}", std::time::Instant::now());
    let mut write_buf = Vec::new();

    let env = ExecutorEnv::builder()
        .stdout(&mut write_buf)
        .build()
        .unwrap();

    let prover = default_prover();

    let receipt = prover.prove_elf(env, METHOD_NAME_ELF).unwrap();
    receipt.verify(METHOD_NAME_ID).unwrap();

    println!("Result: {}", write_buf.len() as u64);
    println!("{:?}", std::time::Instant::now());
}
