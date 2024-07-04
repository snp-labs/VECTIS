mod short_weierstrass;
mod twisted_edwards;
use ark_ff::{Fp, Fp2, Fp2Config, FpConfig};

pub trait Solidity {
    fn to_solidity(&self) -> Vec<String>;
}

impl<P: FpConfig<N>, const N: usize> Solidity for Fp<P, N> {
    fn to_solidity(&self) -> Vec<String> {
        vec![self.to_string()]
    }
}

impl<P: Fp2Config> Solidity for Fp2<P> {
    fn to_solidity(&self) -> Vec<String> {
        vec![self.c1.to_string(), self.c0.to_string()]
    }
}

impl<T: Solidity> Solidity for Vec<T> {
    fn to_solidity(&self) -> Vec<String> {
        self.iter().map(|x| x.to_solidity()).flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Projective, G2Projective};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;

    #[test]
    fn solidity() {
        let mut rng = ark_std::test_rng();
        let g1_projective = G1Projective::rand(&mut rng);
        let g2_projective = G2Projective::rand(&mut rng);
        let g1_affine = g1_projective.into_affine();
        let g2_affine = g2_projective.into_affine();
        let g1_projective_solidity = g1_projective.to_solidity();
        let g1_affine_solidity = g1_affine.to_solidity();
        let g2_affine_solidity = g2_affine.to_solidity();
        println!("{:?}", g1_projective_solidity);
        println!("{:?}", g1_affine_solidity);
        assert_eq!(g1_affine_solidity.len(), 2);
        assert_eq!(g2_affine_solidity.len(), 4);
    }
}
