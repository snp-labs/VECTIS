use ark_ec::AffineRepr;
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use bccgroth16::crypto::commitment::CM;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::ffi::{c_char, CStr};

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct G1Json {
    X: String,
    Y: String,
}

#[allow(dead_code)]
pub fn to_g1_json<E: Pairing>(cm_list: Vec<E::G1Affine>) -> Vec<G1Json> {
    cm_list
        .iter()
        .map(|cm| G1Json {
            X: cm.x().unwrap().to_string(),
            Y: cm.y().unwrap().to_string(),
        })
        .collect()
}

pub fn str_from_c_str<'a>(ptr: *const c_char) -> &'a str {
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let str = c_str.to_str().expect("Invalid UTF-8");
    str
}

pub fn hex_to_scalar<E: Pairing>(hex: &str) -> E::ScalarField {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(format!("{:0>64}", hex)).unwrap();

    // CHECK
    E::ScalarField::from_be_bytes_mod_order(&bytes)
}

pub fn cm_list_from_c_str<E: Pairing>(
    msg_ptr: *const c_char,
    rand_ptr: *const c_char,
) -> Vec<CM<E::ScalarField>> {
    let delimiter = ',';
    let msg_list: Vec<&str> = str_from_c_str(msg_ptr).split(delimiter).collect();
    let rand_list: Vec<&str> = str_from_c_str(rand_ptr).split(delimiter).collect();
    msg_list
        .iter()
        .zip(rand_list.iter())
        .map(|(&msg, &rand)| CM::<E::ScalarField>::from((msg, rand)))
        .collect()
}

/// SHA3 구현
pub fn compute_hash<E>(points: &[E::G1Affine]) -> E::ScalarField
where
    E: Pairing,
{
    let mut hasher = Keccak256::new();

    let mut update = |v: &<E::G1Affine as AffineRepr>::BaseField| {
        let s = v.to_string();
        let scalar = s.parse::<E::ScalarField>().ok().unwrap();
        let bytes: Vec<u8> = scalar.into_bigint().to_bytes_be();
        hasher.update(&bytes);
    };

    points.iter().for_each(|p| {
        let (x, y) = p.xy().unwrap();
        update(x);
        update(y);
    });

    let mut raw = vec![0u8; 32];
    raw.copy_from_slice(&hasher.finalize());

    let hash = E::ScalarField::from_be_bytes_mod_order(&raw);

    hash
}

#[cfg(test)]
mod util_tests {
    use super::*;
    use std::ffi::CString;
    type E = ark_bn254::Bn254;
    type F = ark_bn254::Fr;

    #[test]
    fn str_from_c_str_test() {
        let str = "hello world";
        let str_cstring = CString::new(str).unwrap();
        let c_str = str_cstring.as_ptr();
        let str_result = str_from_c_str(c_str);
        assert_eq!(str_result, str);
    }

    #[test]
    fn hex_to_scalar_test() {
        let hex = "0x01";
        let scalar = hex_to_scalar::<E>(hex);
        assert_eq!(scalar, F::from(1));
    }

    #[test]
    fn cm_list_from_c_str_test() {
        let msg = "1";
        let rand = "2";
        let expect_cm_vec = [CM::<<E as Pairing>::ScalarField>::from((msg, rand))];
        let msg = CString::new(msg).unwrap();
        let rand = CString::new(rand).unwrap();
        let cm_vec = cm_list_from_c_str::<E>(msg.as_ptr(), rand.as_ptr());
        assert_eq!(cm_vec, expect_cm_vec);
    }
}
