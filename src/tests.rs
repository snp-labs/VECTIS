use crate::{
    create_random_proof_incl_cp_link, generate_random_parameters_incl_cp_link, mock::{write_to_raw_data_file}, prepare_verifying_key, verify_proof_incl_cp_link, Commitments, LinkPublicGenerators
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_std::{
    end_timer, rand::{rngs::StdRng, RngCore, SeedableRng}, start_timer, UniformRand
};
use ark_ec::VariableBaseMSM;

/// Circuit for Pedersen commitment, in which `a` is a meesage
#[derive(Clone)]
struct PedersenCircuit<F: Field> {
    m: Vec<Option<F>>,
}

// NOTE: It is necessary to allocate the witness variables that need to be committed before any other
// variable is allocated. This can however be a limitation when a commitment to some indirect witnesses
// (ones that are computed in the circuit) is needed.
impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for PedersenCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        for _m in self.m.iter() {
            cs.new_witness_variable(|| _m.ok_or(SynthesisError::AssignmentMissing))?;
        }

        Ok(())
    }
}

// NOTE: We set the length of message to `ONE`
pub fn get_link_public_gens<R: RngCore, E: Pairing>(
    rng: &mut R,
    count: u32,
) -> LinkPublicGenerators<E> {
    let pedersen_gens = (0..count)
        .map(|_| E::G1::rand(rng).into_affine())
        .collect::<Vec<_>>();
    let g1 = E::G1::rand(rng).into_affine();
    let g2 = E::G2::rand(rng).into_affine();
    LinkPublicGenerators {
        pedersen_gens,
        g1,
        g2,
    }
}

fn test_prove_and_verify<E>(tc: u32)
where
    E: Pairing,
{
    fn run<E: Pairing>(commit_witness_count: u32) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let m: Vec<Option<E::ScalarField>> = (0..commit_witness_count)
            .map(|_| Some(E::ScalarField::rand(&mut rng)))
            .collect();

        let circuit = PedersenCircuit { m: m.clone() };

        // Generators for committing to witnesses and 1 more for randomness (`link_v` below)
        let link_gens = get_link_public_gens(&mut rng, 2);

        // Parameters for generating proof containing CP_link as well
        let params_link = generate_random_parameters_incl_cp_link::<E, _, _>(
            circuit.clone(),
            link_gens.clone(),
            commit_witness_count,
            &mut rng,
        )
        .unwrap();

        // Verifying key for LegoGroth16 including the link public params
        let pvk_link = prepare_verifying_key::<E>(&params_link.vk.groth16_vk);

        // Randomness for the committed witness in proof.d
        let v = E::ScalarField::rand(&mut rng);
        // Randomness for the committed witness in CP_link
        let link_v = E::ScalarField::rand(&mut rng);

        let circuit = PedersenCircuit { m : m.clone() };

        // Create a LegoGro16 proof with CP_link.
        let proof_link =
            create_random_proof_incl_cp_link(circuit.clone(), v, link_v, &params_link, &mut rng)
                .unwrap();

    
        let message_and_opening: Vec<Vec<<E::ScalarField as PrimeField>::BigInt>> = m
            .iter()
            .map(|w| {
                let mut _v = Vec::new();
                _v.push(w.unwrap().into_bigint());
                _v.push(link_v.into_bigint());
                _v
            })
            .collect();
    
        let mut link_com: Vec<E::G1Affine> = Vec::new();

        for e in message_and_opening.iter() {
            link_com.push(E::G1::msm_bigint(&params_link.vk.link_bases, e).into_affine());
        }

        let commitments = Commitments {
            link_com,
            proof_dependent_com: proof_link.groth16_proof.d
        };

        #[cfg(feature = "mock")]
        {
            println!("\nvk size: {:?}", params_link.vk.compressed_size());
            println!("pk size: {:?}", params_link.compressed_size());
            println!("proof size: {:?}\n", proof_link.compressed_size());

            if let Err(e) = write_to_raw_data_file::<E>(commit_witness_count,&params_link.vk, &proof_link, &commitments) {
                println!("Error writing data to file: {}", e);
            }
        }
        
        // Verify LegoGroth16 proof and CP_link proof
        let verifier_time = start_timer!(|| "LegoGroth16::Verifier");
        verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &commitments, &[]).unwrap();
        end_timer!(verifier_time);
    }

    run::<E>(tc);
}

mod bls12_377 {
    use super::*;
    use ark_bls12_377::Bls12_377;

    #[test]
    fn prove_and_verify() {
        for i in 0..=20 {
            test_prove_and_verify::<Bls12_377>(1 << i);
        }
    }
}

mod bls12_381 {
    use super::*;
    use ark_bls12_381::Bls12_381;

    #[test]
    fn prove_and_verify() {
        for i in 0..=20 {
            println!("\nBatch size: {:?}\n", 1 << i);
            test_prove_and_verify::<Bls12_381>(1 << i);
        }
    }
}

mod bn254 {
    use super::*;
    use ark_bn254::Bn254;

    #[test]
    fn prove_and_verify() {
        for i in 0..=10 {
            test_prove_and_verify::<Bn254>(1 << i);
        }
    }
}
