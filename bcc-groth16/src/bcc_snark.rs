use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};

/// The basic functionality for a batched cc-SNARK.
pub trait BccSNARK<E: Pairing, F: PrimeField> {
    /// The information required by the prover to produce a proof for a specific
    /// circuit *C*.
    type ProvingKey: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// The information required by the verifier to check a proof for a specific
    /// circuit *C*.
    type VerifyingKey: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// The information required by the verifier to check a proof for a specific
    /// circuit *C*.
    type CommittingKey: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// The proof output by the prover.
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// The commitment output by the prover.
    type Commitment: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// This contains the verification key, but preprocessed to enable faster
    /// verification.
    type ProcessedVerifyingKey: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// Errors encountered during setup, proving, or verification.
    type Error: 'static + ark_std::error::Error;

    /// Takes in a description of a computation (specified in R1CS constraints),
    /// and samples proving and verification keys for that circuit.
    fn circuit_specific_setup<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error>;

    /// Generates a proof dependent commitment
    /// Get the commitment and opening with challenge
    fn commit<R: RngCore + CryptoRng>(
        circuit_ck: &Self::CommittingKey,
        committed_witness: &[F],
        rng: &mut R,
    ) -> Result<(Vec<E::G1Affine>, Self::Commitment, F), Self::Error>;

    /// Generates a proof of satisfaction of the arithmetic circuit C (specified
    /// as R1CS constraints).
    fn prove<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        circuit_pk: &Self::ProvingKey,
        circuit: C,
        proof_dependent_cm: &Self::Commitment,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>;

    /// Checks that `proof` is a valid proof of the satisfaction of circuit
    /// encoded in `circuit_vk`, with respect to the public input `public_input`,
    /// specified as R1CS constraints.
    /// `public_inputs`: list of commitment and proof dependent commitment
    fn verify(
        circuit_vk: &Self::VerifyingKey,
        proof: &Self::Proof,
        public_inputs: &[E::G1Affine],
    ) -> Result<bool, Self::Error> {
        let pvk = Self::process_vk(circuit_vk)?;
        Self::verify_with_processed_vk(&pvk, proof, public_inputs)
    }

    /// Preprocesses `circuit_vk` to enable faster verification.
    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error>;

    /// Checks that `proof` is a valid proof of the satisfaction of circuit
    /// encoded in `circuit_pvk`, with respect to the public input `public_input`,
    /// specified as R1CS constraints.
    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        proof: &Self::Proof,
        public_inputs: &[E::G1Affine],
    ) -> Result<bool, Self::Error>;
}

/// A ccSNARK with (only) circuit-specific setup.
pub trait CircuitSpecificSetupBccSNARK<E: Pairing, F: PrimeField>: BccSNARK<E, F> {
    /// The setup algorithm for circuit-specific SNARKs. By default, this
    /// just invokes `<Self as SNARK<F>>::circuit_specific_setup(...)`.
    fn setup<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        <Self as BccSNARK<E, F>>::circuit_specific_setup(circuit, rng)
    }
}
