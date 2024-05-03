mod circuit;
mod utils;

#[cfg(test)]
mod tests;

use crate::circuit::BccCircuit;
use crate::utils::cm_list_from_c_str;
use ark_ec::pairing::Pairing;
use bccgroth16::{bcc_snark::*, utils::ToVec, BccGroth16, Proof, ProvingKey, VerifyingKey};

use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use std::sync::RwLock;
use std::{
    ffi::{c_char, CString},
    fs,
    ops::Mul,
};
use utils::{hex_to_scalar, str_from_c_str};

#[macro_use]
extern crate ark_std;

#[macro_use]
extern crate lazy_static;

type E = ark_bn254::Bn254;
type F = ark_bn254::Fr;

lazy_static! {
    pub static ref PK_FILE: String = "cbdc.pk.dat".to_string();
    pub static ref VK_FILE: String = "cbdc.vk.dat".to_string();
    pub static ref PRF_FILE: String = "cbdc.proof.dat".to_string();
    static ref PK: RwLock<ProvingKey<E>> = RwLock::new(ProvingKey::default());
    static ref CK: RwLock<[<E as Pairing>::G1Affine; 2]> =
        RwLock::new([<E as Pairing>::G1Affine::zero(); 2]);
}

#[no_mangle]
pub extern "C" fn setup_bn254(param_path: *const c_char, users: usize) -> bool {
    // Path prefix
    let path = utils::str_from_c_str(param_path);

    let pk_file = format!("{}{}", path, PK_FILE.as_str());
    let vk_file = format!("{}{}", path, VK_FILE.as_str());

    let modified_users = users.next_power_of_two();

    // WARNING: seed
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let mock_circuit = BccCircuit::default(modified_users);

    println!("# User : {}, # modified user: {}", users, modified_users);

    // Generate a common reference string a for cbdc circuit
    let num_committed_witness = 2 * (modified_users + 1) + 1;
    let (pk, vk) = BccGroth16::<E>::setup(mock_circuit, num_committed_witness, &mut rng).unwrap();

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();

    // Write data in .dat
    fs::write(pk_file.as_str(), pk_bytes).unwrap();
    fs::write(vk_file.as_str(), vk_bytes).unwrap();

    let mut _pk = PK.write().unwrap();
    *_pk = pk;

    // TODO: To be more fancy structure such as .json format
    let mut _ck = CK.write().unwrap();
    *_ck = [_pk.ck.batched[0].clone(), _pk.ck.batched[1].clone()];

    true
}

#[no_mangle]
pub extern "C" fn init_bn254(param_path: *const c_char) -> bool {
    let path = str_from_c_str(param_path);

    let pk_file = format!("{}{}", path, PK_FILE.as_str());
    let pk = ProvingKey::<E>::from(pk_file);
    let mut _pk = PK.write().unwrap();
    *_pk = pk;

    let mut _ck = CK.write().unwrap();
    *_ck = [_pk.ck.batched[0].clone(), _pk.ck.batched[1].clone()];
    true
}

#[no_mangle]
pub extern "C" fn get_vk_bn254(param_path: *const c_char) -> *mut c_char {
    let path = str_from_c_str(param_path);
    let vk_file = format!("{}{}", path, VK_FILE.as_str());
    let vk = VerifyingKey::<E>::from(vk_file);
    let c_string_vk = CString::new(vk.to_string()).expect("CString::new failed");
    c_string_vk.into_raw()
}

#[no_mangle]
pub extern "C" fn prove_bn254(
    param_path: *const c_char,
    msg_ptr: *const c_char,
    rand_ptr: *const c_char,
) -> *mut c_char {
    // WARNING: seed
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let pk = PK.read().unwrap();

    // Convert msg_ptr, rand_ptr to CM
    let list_cm = cm_list_from_c_str::<E>(msg_ptr, rand_ptr);

    let committed_witness: Vec<_> = list_cm.iter().flat_map(|&cm| [cm.msg, cm.rand]).collect();

    println!("Commit proof dependent");
    let (_list_cm_g1, proof_dependent_cm, tau) =
        BccGroth16::<E>::commit(&pk.ck, committed_witness.as_slice(), &mut rng).unwrap();

    println!("Commitment generation done...");

    let circuit = BccCircuit::<F>::new(list_cm, tau);

    println!("Generate proof...");
    let proof = BccGroth16::<E>::prove(&pk, circuit, &proof_dependent_cm, &mut rng).unwrap();
    let mut proof_byte = Vec::new();
    proof.serialize_compressed(&mut proof_byte).unwrap();

    // Path prefix
    let path = str_from_c_str(param_path);
    let prf_file = format!("{}{}", path, PRF_FILE.as_str());

    fs::write(prf_file, proof_byte).unwrap();
    println!("Proof generation done...");
    let c_string_proof = CString::new(proof.to_string()).unwrap();
    c_string_proof.into_raw()
}

#[no_mangle]
pub extern "C" fn get_proof_bn254(proof_path: *const c_char) -> *mut c_char {
    // Path prefix
    let path = str_from_c_str(proof_path);
    let prf_file = format!("{}{}", path, PRF_FILE.as_str());

    let proof = Proof::<E>::from(prf_file);
    let c_string_proof = CString::new(proof.to_string()).expect("CString::new failed");

    c_string_proof.into_raw()
}

#[no_mangle]
pub extern "C" fn compute_cm_bn254(
    hex_m_ptr: *const c_char,
    hex_r_ptr: *const c_char,
) -> *mut c_char {
    let ck = CK.read().unwrap();

    let m = hex_to_scalar::<E>(str_from_c_str(hex_m_ptr));
    let r = hex_to_scalar::<E>(str_from_c_str(hex_r_ptr));

    let cm = (ck[0].mul(m) + ck[1].mul(r)).into_affine();

    let cm_c_char = CString::new(format!("({}, {})", cm.x, cm.y).as_str()).expect("cm failed");
    cm_c_char.into_raw()
}

#[cfg(test)]
mod lib_tests {
    use super::*;
    use crate::setup_bn254;
    const PATH: &str = "./";
    const N: usize = 8;

    #[test]
    fn setup_prove_test() {
        let c_path = CString::new(PATH).unwrap();
        let c_path = c_path.as_ptr();

        let is_success = setup_bn254(c_path, N);
        assert!(is_success);

        let vec = vec!["1"; N];

        let vec_string = vec.join(",");
        let vec_ptr = CString::new(vec_string).unwrap();
        let vec_ptr = vec_ptr.as_ptr();
        let proof = prove_bn254(c_path, vec_ptr, vec_ptr);
        let proof = str_from_c_str(proof);
        assert!(!proof.is_empty());

        let obtained_proof = get_proof_bn254(c_path);
        let obtained_proof = str_from_c_str(obtained_proof);
        assert_eq!(proof, obtained_proof);

        let vk = get_vk_bn254(c_path);
        let vk = str_from_c_str(vk);
        assert!(!vk.is_empty());
    }

    #[test]
    fn setup_init_prove_test() {
        let c_path = CString::new(PATH).unwrap();
        let c_path = c_path.as_ptr();

        let is_success = setup_bn254(c_path, N);
        assert!(is_success);

        let is_success = init_bn254(c_path);
        assert!(is_success);

        let vec = vec!["1"; N];
        let vec_string = vec.join(",");
        let vec_ptr = CString::new(vec_string).unwrap();
        let vec_ptr = vec_ptr.as_ptr();
        let proof = prove_bn254(c_path, vec_ptr, vec_ptr);
        let proof = str_from_c_str(proof);
        assert!(!proof.is_empty());

        let obtained_proof = get_proof_bn254(c_path);
        let obtained_proof = str_from_c_str(obtained_proof);
        assert_eq!(proof, obtained_proof);

        let vk = get_vk_bn254(c_path);
        let vk = str_from_c_str(vk);
        assert!(!vk.is_empty());
    }

    // 수정 필요
    // #[test]
    // fn compute_cm_bn254_test() {
    //     let hex = CString::new("0x123").unwrap();
    //     let hex = hex.as_ptr();
    //     let cm = compute_cm_bn254(hex, hex);
    //     let cm = str_from_c_str(cm);
    //     let expected_cm = "(6466513494921947375569267478814063536154272582123927482381877901754572934391, 6126728972616263110126865122705165162529680719771750131682365931647554952432)";
    //     assert_eq!(cm, expected_cm);
    // }
}
