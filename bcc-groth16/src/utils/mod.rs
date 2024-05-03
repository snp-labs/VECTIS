use ark_ec::AffineRepr;

pub trait ToVec<F> {
    fn to_vec(&self) -> Vec<String>;
}

impl ToVec<ark_bn254::Fq> for ark_bn254::G1Affine {
    fn to_vec(&self) -> Vec<String> {
        let mut v = Vec::new();
        v.push(self.x().unwrap().to_string());
        v.push(self.y().unwrap().to_string());
        v
    }
}

impl ToVec<ark_bn254::Fq2> for ark_bn254::G2Affine {
    fn to_vec(&self) -> Vec<String> {
        let mut v = Vec::new();
        v.push(self.x().unwrap().c1.to_string());
        v.push(self.x().unwrap().c0.to_string());
        v.push(self.y().unwrap().c1.to_string());
        v.push(self.y().unwrap().c0.to_string());
        v
    }
}
