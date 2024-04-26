use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::*;
use ark_std::vec::Vec;
use core::ops::Neg;
use std::fs::{self, File};
use std::path::Path;

/// Read Vec<u8> from file
pub fn read_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let mut f = File::open(&path).expect("no file found");
    let metadata = fs::metadata(&path).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

/// A commitment in the cc-SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<E: Pairing> {
    /// The commitment
    pub cm: E::G1Affine,
    /// The opening of the commitment
    pub opening: E::ScalarField,
}

impl<E: Pairing> Default for Commitment<E> {
    fn default() -> Self {
        Self {
            cm: E::G1Affine::default(),
            opening: E::ScalarField::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    /// The `A` element in `G1`.
    pub a: E::G1Affine,
    /// The `B` element in `G2`.
    pub b: E::G2Affine,
    /// The `C` element in `G1`.
    pub c: E::G1Affine,
}

impl<E: Pairing> Default for Proof<E> {
    fn default() -> Self {
        Self {
            a: E::G1Affine::default(),
            b: E::G2Affine::default(),
            c: E::G1Affine::default(),
        }
    }
}

// Read Proof from path
impl<E: Pairing, P: AsRef<Path>> From<P> for Proof<E> {
    fn from(path: P) -> Self {
        let raw_proof = read_file(path);
        let proof = Proof::<E>::deserialize_compressed(raw_proof.as_slice()).unwrap();

        proof
    }
}

impl<E: Pairing> ToString for Proof<E> {
    fn to_string(&self) -> String {
        serde_json::json!({
            "a" : format!("{:#?}", self.a),
            "b" : format!("{:#?}", self.b),
            "c" : format!("{:#?}", self.c),
        })
        .to_string()
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A commitment key in the LegoSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommittingKey<E: Pairing> {
    /// For [Batched cc-SNARK]
    /// length of the batched commitment key <M + 1>
    pub batched: Vec<E::G1Affine>,

    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H` with The 'eta/gamma * G'
    /// where `G` is the generator of `E::G1`.
    pub proof_dependent: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for CommittingKey<E> {
    fn default() -> Self {
        Self {
            batched: Vec::new(),
            proof_dependent: Vec::new(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 cc-SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: E::G1Affine,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: E::G2Affine,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: E::G2Affine,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: E::G2Affine,

    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is
    /// the generator of `E::G1`
    /// for Batched cc-SNARK [1, tau: challenge)]
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for VerifyingKey<E> {
    fn default() -> Self {
        Self {
            alpha_g1: E::G1Affine::default(),
            beta_g2: E::G2Affine::default(),
            gamma_g2: E::G2Affine::default(),
            delta_g2: E::G2Affine::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

// Read VerifyingKey from path
impl<E: Pairing, P: AsRef<Path>> From<P> for VerifyingKey<E> {
    fn from(path: P) -> Self {
        let raw_vk = read_file(path);
        let vk = VerifyingKey::<E>::deserialize_compressed(raw_vk.as_slice()).unwrap();

        vk
    }
}

impl<E: Pairing> ToString for VerifyingKey<E> {
    fn to_string(&self) -> String {
        serde_json::json!({
            "alpha" : format!("{:#?}", self.alpha_g1),
            "beta" : format!("{:#?}", (self.beta_g2.into_group().neg()).into_affine()),
            "delta" : format!("{:#?}", (self.delta_g2.into_group().neg()).into_affine()),
            "gamma" : format!("{:#?}", (self.gamma_g2.into_group().neg()).into_affine()),
            "abc" : format!("{:#?}", self.gamma_abc_g1)
        })
        .to_string()
    }
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifyingKey<E: Pairing> {
    /// The unprepared verification key.
    pub vk: VerifyingKey<E>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: E::TargetField,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: E::G2Prepared,
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: E::G2Prepared,
}

impl<E: Pairing> From<PreparedVerifyingKey<E>> for VerifyingKey<E> {
    fn from(other: PreparedVerifyingKey<E>) -> Self {
        other.vk
    }
}

impl<E: Pairing> From<VerifyingKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: VerifyingKey<E>) -> Self {
        crate::prepare_verifying_key(&other)
    }
}

impl<E: Pairing> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            alpha_g1_beta_g2: E::TargetField::default(),
            gamma_g2_neg_pc: E::G2Prepared::default(),
            delta_g2_neg_pc: E::G2Prepared::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// The prover key for for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// The underlying verification key.
    pub vk: VerifyingKey<E>,
    /// The underlying commitment key.
    pub ck: CommittingKey<E>,
    /// The element `beta * G` in `E::G1`.
    pub beta_g1: E::G1Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: E::G1Affine,
    /// The 'eta/delta * G', where `G` is the generator of `E::G1`.
    pub delta_eta_g1: E::G1Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: Vec<E::G1Affine>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: Vec<E::G1Affine>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: Vec<E::G2Affine>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: Vec<E::G1Affine>,
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for ProvingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            ck: CommittingKey::default(),
            beta_g1: E::G1Affine::default(),
            delta_g1: E::G1Affine::default(),
            delta_eta_g1: E::G1Affine::default(),
            a_query: Vec::new(),
            b_g1_query: Vec::new(),
            b_g2_query: Vec::new(),
            h_query: Vec::new(),
            l_query: Vec::new(),
        }
    }
}

impl<E: Pairing, P: AsRef<Path>> From<P> for ProvingKey<E> {
    fn from(path: P) -> Self {
        let raw_pk = read_file(path);
        let pk = ProvingKey::<E>::deserialize_compressed(raw_pk.as_slice()).unwrap();

        pk
    }
}
