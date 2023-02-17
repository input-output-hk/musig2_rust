//! Implementation of MuSig2 as defined in the paper by Nick, Ruffing and Seurin,
//! [MuSig2: Simple Two-Round Schnorr Multi-Signatures](https://eprint.iacr.org/2020/1261.pdf).
#![warn(missing_docs, rust_2018_idioms)]
#![allow(non_snake_case)]
#![allow(dead_code)]
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Sha512;
use rand_core::{CryptoRng, RngCore};

const NR_MESSAGES: usize = 2;
const NONCE: usize = 2;

/// The list of signer's commitments of size NONCE
pub type RComms = [Commitment; NONCE];

/// The list of signer's commitments for all messages to be signed
pub type BatchedR = [RComms; NR_MESSAGES];

#[derive(Debug, Default)]
/// MuSig2 keypair
pub struct KeyPair {
    sk: Scalar,
    pk: RistrettoPoint,
}

#[derive(Debug, Default)]
/// Commitment with opening
pub struct CommitmentWithOpening {
    msg: Scalar,
    comm: Commitment,
}

/// Signer's commitment
pub type Commitment = RistrettoPoint;

#[derive(Debug, Default, Clone)]
/// MuSig2 context
pub struct Musig2Context {
    aggr_pubkey: RistrettoPoint,
    aggr_R_list: BatchedR,
    L: Vec<u8>, // todo: Do we need the vec?
    /// The number of participants
    pub nr_signers: usize,
    /// The number of messages to be signed
    pub nr_messages: usize,
}

#[derive(Debug, Default)]
/// Signer strucutre, that holds the Musig2Context, the keypair, it's personal state, and
/// the commitments of the other participants.
pub struct Signer {
    mc: Musig2Context,
    keypair: KeyPair,
    comm_list: [[CommitmentWithOpening; NONCE]; NR_MESSAGES],
    state: usize,
}

#[derive(Debug, Default)]
/// Single signature
pub struct IndividualSignature {
    /// signer's signature
    pub s: Scalar,
    /// Commitment for the state
    pub R: Commitment,
}

impl Musig2Context {
    fn set_L(&mut self, pubkey_list: &[RistrettoPoint]) {
        let mut out: Vec<u8> = Vec::new();
        for pk in pubkey_list {
            out.extend_from_slice(pk.compress().as_bytes())
        }
        self.L = out;
    }

    fn aggregate_pubkey(&mut self, pubkey_list: &[RistrettoPoint]) {
        self.aggr_pubkey = Default::default();
        for pk in pubkey_list {
            let mut temp_L = self.L.clone();
            temp_L.extend_from_slice(pk.compress().as_bytes());
            let a = Scalar::hash_from_bytes::<Sha512>(&temp_L);
            self.aggr_pubkey += pk * a;
        }
    }

    fn aggregate_R(&mut self, batch_list: &[BatchedR]) {
        for signer_batch in batch_list {
            for (i, batch) in signer_batch.iter().enumerate() {
                for (j, comm) in batch.iter().enumerate() {
                    self.aggr_R_list[i][j] += comm;
                }
            }
        }
    }
}

impl KeyPair {
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = Scalar::random(rng);
        let pk = &sk * &constants::RISTRETTO_BASEPOINT_TABLE;
        KeyPair { sk, pk }
    }
}

impl CommitmentWithOpening {
    fn commit<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let msg = Scalar::random(rng);
        let comm = &msg * &constants::RISTRETTO_BASEPOINT_TABLE;
        Self { msg, comm }
    }
}

impl Signer {
    fn init<R: RngCore + CryptoRng>(mc: Musig2Context, rng: &mut R) -> Self {
        let keypair = KeyPair::generate(rng);

        let mut comm_list: [[CommitmentWithOpening; NONCE]; NR_MESSAGES] = Default::default();

        for s in comm_list.iter_mut().take(mc.nr_messages) {
            for _c in s.iter_mut().take(NONCE) {
                CommitmentWithOpening::commit(rng);
            }
        }
        Self {
            mc,
            keypair,
            comm_list,
            state: 0,
        }
    }

    /// The precomputation done before the actual signing process
    pub fn precompute(&mut self, pubkey_list: &[RistrettoPoint], batch_list: &[BatchedR]) {
        self.mc.aggregate_pubkey(pubkey_list);
        self.mc.aggregate_R(batch_list);
    }

    /// Single signature generation
    pub fn sign(&mut self, msg: &[u8]) -> IndividualSignature {
        let mut temp_L = self.mc.L.clone();
        temp_L.extend_from_slice(self.keypair.pk.compress().as_bytes());
        let a = Scalar::hash_from_bytes::<Sha512>(&temp_L);

        let batch: RComms = self.mc.aggr_R_list[self.state];
        let b_list = Signer::compute_b(&self.mc.aggr_pubkey, &batch, msg);
        let R = Signer::compute_R(&batch, &b_list);
        let c = Signer::compute_c(&self.mc.aggr_pubkey, &R, msg);

        let mut s = c * a * self.keypair.sk;
        for (index, b) in b_list.iter().enumerate() {
            s += self.comm_list[self.state][index].msg * b;
        }
        self.state += 1;
        IndividualSignature { s, R }
    }

    fn compute_b(pubkey: &Commitment, batch: &RComms, msg: &[u8]) -> [Scalar; NONCE] {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(pubkey.compress().as_bytes());
        for R in batch {
            b.extend_from_slice(R.compress().as_bytes());
        }
        b.extend_from_slice(msg);
        let mut b_list: [Scalar; NONCE] = Default::default();
        b_list[0] = Scalar::hash_from_bytes::<Sha512>(&b);

        for i in 1..NONCE {
            b_list[i] = b_list[i - 1] * b_list[0];
        }
        b_list
    }

    fn compute_R(batch: &RComms, b_list: &[Scalar]) -> Commitment {
        let mut R: Commitment = Default::default();
        for (index, comm) in batch.iter().enumerate() {
            R += comm * b_list[index];
        }
        R
    }

    fn compute_c(pubkey: &Commitment, R: &Commitment, msg: &[u8]) -> Scalar {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(pubkey.compress().as_bytes());
        bytes.extend_from_slice(R.compress().as_bytes());
        bytes.extend_from_slice(msg);
        Scalar::hash_from_bytes::<Sha512>(&bytes)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const NR_SIGNERS: usize = 2;
    const MSG_1: &[u8] = b"message 1";
    const MSG_2: &[u8] = b"message 2";

    #[test]
    fn test_musig2() {
        let mut signers: [Signer; NR_SIGNERS] = Default::default();
        let mut pubkey_list: [RistrettoPoint; NR_SIGNERS] = Default::default();
        let mut batch_list: [BatchedR; NR_SIGNERS] = Default::default();
        let mut signatures: [IndividualSignature; NR_SIGNERS] = Default::default();

        let mc = Musig2Context {
            aggr_pubkey: Default::default(),
            aggr_R_list: Default::default(),
            L: Default::default(),
            nr_signers: NR_SIGNERS,
            nr_messages: NR_MESSAGES,
        };
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        for (cnt, signer) in signers.iter_mut().enumerate() {
            Signer::init(mc.clone(), &mut rng);
            pubkey_list[cnt] = signer.keypair.pk;

            let batch_comm: BatchedR = Default::default();
            for (i, comm) in batch_comm.into_iter().enumerate() {
                let mut comms: RComms = Default::default();
                for (j, _point) in comm.into_iter().enumerate() {
                    comms[j] = signer.comm_list[i][j].comm;
                }
                batch_list[cnt][i] = comms;
            }
        }
        for signer in signers.iter_mut() {
            signer.precompute(&pubkey_list, &batch_list);
        }

        for (index, _sig) in signatures.iter_mut().enumerate() {
            signers[index].sign(MSG_1);
            assert_eq!(signers[index].state, 1);
        }

        for i in 1..signatures.len() {
            assert_eq!(signatures[0].R, signatures[i].R)
        }
    }
}
