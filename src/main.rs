#![allow(non_snake_case)]
#![allow(dead_code)]

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants;
extern crate rand_core;

const NR_MESSAGES: usize = 2;
const NONCE: usize = 2;


#[derive(Debug, Default)]
pub struct KeyPair {
    sk: Scalar,
    pk: RistrettoPoint,
}

#[derive(Debug)]
pub struct Musig2Context {
    aggr_pubkey: RistrettoPoint,
    aggr_R_list: [[RistrettoPoint; NONCE]; NR_MESSAGES],
    L: Vec<u8>,
    pk_parity: bool,
    pub nr_signers: usize,
    pub nr_messages: usize,
}

#[derive(Debug)]
pub struct Signer {
    mc: Musig2Context,
    keypair: KeyPair,
    comm_list: [[KeyPair; NONCE]; NR_MESSAGES],
    state: i32,
}






impl Signer {
    fn generate_key_pair() -> KeyPair {
        let sk = Scalar::from(999u64);
        let pk = &sk * &constants::RISTRETTO_BASEPOINT_TABLE;
        KeyPair{sk, pk}
    }

    fn musig2_init_signer(mc: Musig2Context) -> Self {
        // let mut uniform_bytes = [0u8; 32];
        // rng.fill_bytes(&mut uniform_bytes);

        let keypair = Signer::generate_key_pair();
        let mut comm_list: [[KeyPair; NONCE]; NR_MESSAGES] = Default::default();
        for i in 0..mc.nr_messages {
            for j in 0..NONCE {
                comm_list[i][j] = Signer::generate_key_pair();
            }
        };
        Self {
            mc,
            keypair,
            comm_list,
            state: 0,
        }
    }

    fn pre_sign_computation(&mut self, pubkey_list: &[RistrettoPoint], batch_list: &[&[&[RistrettoPoint]; NONCE]; NR_MESSAGES]) {
        Musig2Context::set_L(&mut self.mc, pubkey_list);
        Musig2Context::aggregate_pubkey(&mut self.mc, pubkey_list);
        Musig2Context::aggregate_R(&mut self.mc, batch_list);
    }
}

impl Musig2Context {
    pub fn setup (nr_messages: usize) -> Self {
        Self {
            aggr_pubkey: Default::default(),
            aggr_R_list: Default::default(),
            L: Default::default(),
            pk_parity: false,
            nr_signers: 0,
            nr_messages
        }
    }

    pub fn set_L (&mut self, pubkey_list: &[RistrettoPoint]) {
        let mut out: Vec<u8> = Vec::new();
        for pk in pubkey_list {
            out.extend_from_slice(pk.compress().as_bytes())
        }
        self.L = out;
    }

    pub fn aggregate_pubkey(&mut self, pubkey_list: &[RistrettoPoint]) {
        self.aggr_pubkey = Default::default();
        for pk in pubkey_list {
            let mut temp_L = self.L.clone();
            temp_L.extend_from_slice(pk.compress().as_bytes());
            let a = Scalar::from_bytes_mod_order(<[u8; 32]>::try_from(temp_L).unwrap());
            self.aggr_pubkey += pk * a;
        }
    }

    pub fn aggregate_R(&mut self, batch_list: &[&[&[RistrettoPoint]; NONCE]; NR_MESSAGES]) {

        for k in 0..NR_MESSAGES {
            for j in 0..NONCE {
                let mut temp_Point: RistrettoPoint = Default::default();
                for i in 0..self.nr_signers {
                    temp_Point += batch_list[k][j][i];
                }
                self.aggr_R_list[k][j] = temp_Point;
            }
        }
    }
}

fn main() {
    let mc = Musig2Context {
        aggr_pubkey: Default::default(),
        aggr_R_list: Default::default(),
        L: Default::default(),
        pk_parity: false,
        nr_signers: 0,
        nr_messages: NR_MESSAGES
    };

    let signer = Signer::musig2_init_signer(mc);
    print!("{}", signer.keypair.sk.to_bytes().len());
}