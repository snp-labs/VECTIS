#[cfg(test)]
mod test {
    const N: usize = 4;
    use crate::{
        commitment::HomomorphicCommitment,
        constraint_system::{StandardComposer, Variable},
        error::to_pc_error,
        prelude::{verify_proof, Circuit, Error, VerifierData},
        proof_system::Prover,
    };
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{PairingEngine, TEModelParameters};
    use ark_ff::{FftField, PrimeField};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::test_rng;
    use std::{convert::TryInto, marker::PhantomData};

    fn _to_vec<T, const N: usize>(v: Vec<T>) -> [T; N] {
        v.try_into().unwrap_or_else(|v: Vec<T>| {
            panic!("Expected a Vec of length {} but it was {}", N, v.len())
        })
    }

    fn aggregate_vector<F: PrimeField>(var_vec: Vec<F>, rand: F) -> F {
        let mut var_cp_vec = var_vec.clone();
        let mut res = var_cp_vec[0].clone();

        let mut sz = var_cp_vec.len();
        let mut coeff = rand;

        while sz > 1 {
            let even: F = var_cp_vec.iter().skip(1).step_by(2).sum();
            res += even * coeff;

            coeff = coeff.clone() * coeff;
            sz >>= 1;

            for i in 0..sz {
                var_cp_vec[i] = var_cp_vec[i << 1].clone() + &var_cp_vec[(i << 1) + 1];
            }

            var_cp_vec.truncate(sz);
        }

        res
    }

    fn aggregate_variable_vector<F, P>(
        var_vec: Vec<Variable>,
        rand: Variable,
        composer: &mut StandardComposer<F, P>,
    ) -> Result<Variable, Error>
    where
        F: PrimeField,
        P: TEModelParameters<BaseField = F>,
    {
        let mut sz = var_vec.len();
        let mut agg = var_vec[0];

        let mut var_cp_vec = var_vec.clone();
        let mut coeff = rand.clone();

        while sz > 1 {
            let mut sum_var: Variable = composer.add_input(F::zero()); // Init 0
                                                                       // Compute sum result for even idx
            for i in (1..var_cp_vec.len()).step_by(2) {
                sum_var = composer.arithmetic_gate(|gate| {
                    gate.witness(sum_var, var_cp_vec[i], None)
                        .add(F::one(), F::one())
                });
            }

            sum_var =
                composer.arithmetic_gate(|gate| gate.witness(sum_var, coeff, None).mul(F::one()));

            agg = composer
                .arithmetic_gate(|gate| gate.witness(agg, sum_var, None).add(F::one(), F::one()));

            // coeff = coeff * coeff
            coeff = composer.arithmetic_gate(|gate| gate.witness(coeff, coeff, None).mul(F::one()));

            sz >>= 1;

            for i in 0..sz {
                var_cp_vec[i] = composer.arithmetic_gate(|gate| {
                    gate.witness(var_cp_vec[i << 1], var_cp_vec[(i << 1) + 1], None)
                        .add(F::one(), F::one())
                });
            }
            var_cp_vec.truncate(sz);
        }

        Ok(agg)
    }

    // Implements a circuit that checks:

    #[derive(derivative::Derivative)]
    #[derivative(Debug(bound = ""), Default(bound = ""))]
    pub struct TestCircuit<F: FftField, P: TEModelParameters<BaseField = F>> {
        agg: [F; 2],
        m_vec: [F; N],
        o_vec: [F; N],
        rand: F,
        _p: PhantomData<P>,
    }

    impl<F, P> Circuit<F, P> for TestCircuit<F, P>
    where
        F: PrimeField,
        P: TEModelParameters<BaseField = F>,
    {
        const CIRCUIT_ID: [u8; 32] = [0xff; 32];

        fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
            let zero = composer.zero_var;
            let agg_m_expected = composer.arithmetic_gate(|gate| {
                gate.witness(zero, zero, None)
                    .add(F::zero(), F::zero())
                    .cw(self.agg[0])
            });
            let agg_o_expected = composer.arithmetic_gate(|gate| {
                gate.witness(zero, zero, None)
                    .add(F::zero(), F::zero())
                    .cw(self.agg[1])
            });

            let mut m_var_vec: Vec<Variable> = Vec::new();
            let mut o_var_vec: Vec<Variable> = Vec::new();

            for i in 0..N {
                // Committed witness : message_i
                m_var_vec.push(composer.arithmetic_gate(|gate| {
                    gate.witness(zero, zero, None)
                        .add(F::zero(), F::zero())
                        .cw(self.m_vec[i])
                }));

                // Committed witness : opening_i
                o_var_vec.push(composer.arithmetic_gate(|gate| {
                    gate.witness(zero, zero, None)
                        .add(F::zero(), F::zero())
                        .cw(self.o_vec[i])
                }));
            }

            let rand: Variable = composer.add_input(self.rand);
            let agg_m = aggregate_variable_vector(m_var_vec.clone(), rand, composer)?;
            let agg_o = aggregate_variable_vector(o_var_vec.clone(), rand, composer)?;

            // Equality check
            composer.assert_equal(agg_m, agg_m_expected);
            composer.assert_equal(agg_o, agg_o_expected);

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

        let rand = F::rand(&mut test_rng());

        let msg: Vec<F> = (0..N).map(|_| F::rand(&mut test_rng())).collect();
        let open: Vec<F> = (0..N).map(|_| F::rand(&mut test_rng())).collect();

        let agg_m = aggregate_vector(msg.clone(), rand);
        let agg_o = aggregate_vector(open.clone(), rand);

        // Prover POV
        let (proof, pi, _cw) = {
            let mut circuit: TestCircuit<F, P> = TestCircuit {
                agg: [agg_m, agg_o],
                m_vec: _to_vec(msg),
                o_vec: _to_vec(open),
                rand,
                _p: PhantomData,
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
            b"Test"
        )
        .is_ok());

        Ok(())
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_batched_pedersen_full_on_Bls12_381() -> Result<(), Error> {
        test_full::<
            <Bls12_381 as PairingEngine>::Fr,
            ark_ed_on_bls12_381::EdwardsParameters,
            crate::commitment::KZG10<Bls12_381>,
        >()
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_batched_pedersen_full_on_Bls12_377() -> Result<(), Error> {
        test_full::<
            <Bls12_377 as PairingEngine>::Fr,
            ark_ed_on_bls12_377::EdwardsParameters,
            crate::commitment::KZG10<Bls12_377>,
        >()
    }
}
