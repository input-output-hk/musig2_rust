#![allow(non_snake_case)]
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants;

// use ed25519_dalek::{Keypair, Signature, Signer};
// use rand_chacha_dalek_compat::ChaCha20Rng;
// use rand_chacha_dalek_compat::rand_core::{OsRng};
// use rand_core::{CryptoRng, RngCore};

extern crate rand_core;



pub struct KeyPair{
    sk: Scalar,
    pk: RistrettoPoint
}

pub struct Signer{
    keypair: KeyPair,
    comm_list: Option<Vec<KeyPair>>,
    state: usize,
}

impl Signer{
    fn musig2_key_gen() -> Self{
        // let mut uniform_bytes = [0u8; 32];
        // rng.fill_bytes(&mut uniform_bytes);
        let sk = Scalar::from(999u64);
        let pk = &sk * &constants::RISTRETTO_BASEPOINT_TABLE;
        let keypair = KeyPair{sk, pk};
        Self{
            keypair,
            comm_list: None,
            state: 0,
        }
    }

}


fn main() {
    let signer = Signer::musig2_key_gen();
    print!("{}", signer.keypair.sk.to_bytes().len());
}