use crate::{
    commitment::HomomorphicCommitment,
    error::{to_pc_error, Error},
    prelude::StandardComposer,
    proof_system::{
        cw::CommittedWitness, pi::PublicInputs, Proof, Prover, ProverKey, Verifier, VerifierKey,
    },
};
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_serialize::*;

#[cfg(test)]
mod test {
    const N: usize = 4;

    use super::*;
    use crate::{
        constraint_system::{ecc::Point, StandardComposer, Variable},
        prelude::{verify_proof, Circuit, Error, VerifierData},
        util,
    };
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{
        twisted_edwards_extended::GroupAffine, AffineCurve, PairingEngine, ProjectiveCurve,
        TEModelParameters,
    };
    use ark_ff::{FftField, PrimeField, UniformRand};
    use ark_std::test_rng;
    use std::convert::TryInto;

    fn _to_vec<T, const N: usize>(v: Vec<T>) -> [T; N] {
        v.try_into().unwrap_or_else(|v: Vec<T>| {
            panic!("Expected a Vec of length {} but it was {}", N, v.len())
        })
    }

    // Implements a circuit that checks:
    // forall i , cm_i = Ped(ck, m_i; o_i)
    #[derive(derivative::Derivative)]
    #[derivative(Debug(bound = ""), Default(bound = ""))]
    pub struct TestCircuit<F: FftField, P: TEModelParameters<BaseField = F>> {
        ck: [GroupAffine<P>; 2],
        msg: [P::ScalarField; N],
        open: [P::ScalarField; N],
        cm: [GroupAffine<P>; N],
    }

    impl<F, P> Circuit<F, P> for TestCircuit<F, P>
    where
        F: PrimeField,
        P: TEModelParameters<BaseField = F>,
    {
        const CIRCUIT_ID: [u8; 32] = [0xff; 32];

        fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
            let ck_var_vec: Vec<Point<P>> =
                self.ck.iter().map(|ck| composer.add_affine(*ck)).collect();
            let msg_var_vec: Vec<Variable> = self
                .msg
                .iter()
                .map(|m| composer.add_input(util::from_embedded_curve_scalar::<F, P>(*m)))
                .collect();
            let open_var_vec: Vec<Variable> = self
                .open
                .iter()
                .map(|o| composer.add_input(util::from_embedded_curve_scalar::<F, P>(*o)))
                .collect();

            for i in 0..N {
                let p1: Point<P> = composer.variable_base_scalar_mul(msg_var_vec[i], ck_var_vec[0]);
                let p2: Point<P> =
                    composer.variable_base_scalar_mul(open_var_vec[i], ck_var_vec[1]);
                let cm_expected: Point<P> = composer.point_addition_gate(p1, p2);
                composer.assert_equal_public_point(cm_expected, self.cm[i]);
            }

            Ok(())
        }

        fn padded_circuit_size(&self) -> usize {
            1 << 15
        }
    }

    fn test_full<F, P, PC>() -> Result<(), Error>
    where
        F: PrimeField,
        P: TEModelParameters<BaseField = F>,
        PC: HomomorphicCommitment<F>,
        VerifierData<F, PC>: PartialEq,
    {
        // Generate CRS
        let pp = PC::setup(1 << 16, None, &mut test_rng()).map_err(to_pc_error::<F, PC>)?;

        let mut circuit = TestCircuit::<F, P>::default();

        // Compile the circuit
        let (pk, (vk, _pi_pos)) = circuit.compile::<PC>(&pp)?;

        let ck: Vec<GroupAffine<P>> = (0..2).map(|_| GroupAffine::rand(&mut test_rng())).collect();
        let msg: Vec<P::ScalarField> = (0..N)
            .map(|_| P::ScalarField::rand(&mut test_rng()))
            .collect();
        let open: Vec<P::ScalarField> = (0..N)
            .map(|_| P::ScalarField::rand(&mut test_rng()))
            .collect();

        let cm: Vec<GroupAffine<P>> = msg
            .iter()
            .zip(open.iter())
            .map(|(m, o)| {
                (AffineCurve::mul(&ck[0], m.into_repr()) + AffineCurve::mul(&ck[1], o.into_repr()))
                    .into_affine()
            })
            .collect();

        // Prover POV
        let (proof, pi, cw) = {
            let mut circuit: TestCircuit<F, P> = TestCircuit {
                ck: _to_vec(ck),
                msg: _to_vec(msg),
                open: _to_vec(open),
                cm: _to_vec(cm),
            };

            cfg_if::cfg_if! {
                if #[cfg(feature = "trace")] {
                    // Test trace
                    let mut prover: Prover<F, P, PC> = Prover::new(b"Test");
                    circuit.gadget(prover.mut_cs())?;
                    prover.cs.check_circuit_satisfied();
                }
            }

            circuit.gen_proof::<PC>(&pp, pk, b"Test")?
        };

        let verifier_data = VerifierData::new(vk, pi);

        // Test serialisation for verifier_data
        let mut verifier_data_bytes = Vec::new();
        verifier_data.serialize(&mut verifier_data_bytes).unwrap();

        let deserialized_verifier_data: VerifierData<F, PC> =
            VerifierData::deserialize(verifier_data_bytes.as_slice()).unwrap();

        assert!(deserialized_verifier_data == verifier_data);

        assert!(verify_proof::<F, P, PC>(
            &pp,
            verifier_data.key,
            &proof,
            &verifier_data.pi,
            b"Test",
        )
        .is_ok());

        Ok(())
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_pedersen_full_on_Bls12_381() -> Result<(), Error> {
        test_full::<
            <Bls12_381 as PairingEngine>::Fr,
            ark_ed_on_bls12_381::EdwardsParameters,
            crate::commitment::KZG10<Bls12_381>,
        >()
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_pedersen_full_on_Bls12_377() -> Result<(), Error> {
        test_full::<
            <Bls12_377 as PairingEngine>::Fr,
            ark_ed_on_bls12_377::EdwardsParameters,
            crate::commitment::KZG10<Bls12_377>,
        >()
    }
}
