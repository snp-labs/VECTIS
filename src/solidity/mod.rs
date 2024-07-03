use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Fp, Fp2, Fp2Config, FpConfig};

pub trait Solidity {
    fn to_solidity(&self) -> Vec<String>;
}

impl<P: FpConfig<N>, const N: usize> Solidity for Fp<P, N> {
    fn to_solidity(&self) -> Vec<String> {
        unimplemented!()
    }
}
impl<P: Fp2Config> Solidity for Fp2<P> {
    fn to_solidity(&self) -> Vec<String> {
        unimplemented!()
    }
}
