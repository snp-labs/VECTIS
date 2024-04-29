use ark_ec::{pairing::Pairing, CurveGroup, AffineRepr};
use std::{fs::File, ops::Neg};
use crate::{Commitments, ProofWithLink, VerifyingKeyWithLink};
use std::io::{Write, Result};


pub fn vk_groth_to_string<E: Pairing>(vk: &VerifyingKeyWithLink<E>) -> String {
    serde_json::json!({
        "alpha" : format!("{:#?}", vk.groth16_vk.alpha_g1),
        "beta" : format!("{:#?}", (vk.groth16_vk.beta_g2.into_group().neg()).into_affine()),
        "delta" : format!("{:#?}", (vk.groth16_vk.delta_g2.into_group().neg()).into_affine()),
        "abc" : format!("{:#?}", vk.groth16_vk.gamma_abc_g1[0]),
        "gamma" : format!("{:#?}", (vk.groth16_vk.gamma_g2.into_group().neg()).into_affine()),
    })
    .to_string()
}

pub fn vk_link_to_string<E: Pairing>(vk: &VerifyingKeyWithLink<E>) -> String {
    serde_json::json!({
        "C" : format!("{:#?}", vk.link_vk.c),
        "a" : format!("{:#?}", (vk.link_vk.a.into_group().neg()).into_affine()),
    })
    .to_string()
}

pub fn proof_groth_to_string<E: Pairing>(proof: &ProofWithLink<E>) -> String {
    serde_json::json!({
        "a" : format!("{:#?}", proof.groth16_proof.a),
        "b" : format!("{:#?}", proof.groth16_proof.b),
        "c" : format!("{:#?}", proof.groth16_proof.c),
        "d" : format!("{:#?}", proof.groth16_proof.d),
    })
    .to_string()
}

pub fn proof_link_to_string<E: Pairing>(proof: &ProofWithLink<E>) -> String {
    serde_json::json!({
        "pi" : format!("{:#?}", proof.link_pi),
    })
    .to_string()
}

pub fn instance_to_string<E: Pairing>(commitments: &Commitments<E>) -> String {
    serde_json::json!({
        "link_com" : format!("{:#?}", commitments.link_com),
        "pd_cm" : format!("{:#?}", commitments.proof_dependent_com),
    })
    .to_string()
}

pub fn write_to_raw_data_file<E: Pairing>(batch_size: u32,vk: &VerifyingKeyWithLink<E>, proof: &ProofWithLink<E>, commitments: &Commitments<E>) -> Result<()> {
    let vk_groth = vk_groth_to_string(vk);
    let vk_link = vk_link_to_string(vk);
    let proof_groth = proof_groth_to_string(proof);
    let proof_link = proof_link_to_string(proof);
    let instance = instance_to_string(commitments);

    let data = serde_json::json!({
        "vk_groth": vk_groth,
        "vk_link": vk_link,
        "proof_groth": proof_groth,
        "proof_link": proof_link,
        "instance": instance
    });
    let mut file = File::create(format!("mock-{:?}.json", batch_size))?;
    file.write_all(data.to_string().as_bytes())?;

    Ok(())
}