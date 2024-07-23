use ark_ec::CurveGroup;

use super::{CompAmComEq, PartialProof, PublicParameters};

impl<C: CurveGroup> CompAmComEq<C> {
    pub fn verify_with_partial_proof(
        pp: &PublicParameters<C>,
        proof: &PartialProof<C>,
    ) -> Result<bool, ()> {
        if proof.z.len() != 2 || proof.z.len() != pp.g.len() || proof.z.len() != pp.g_hat.len() {
            return Err(());
        }
        let y_real = (pp.g[0] * proof.z[0] + pp.g[1] * proof.z[1]).into_affine();
        let y_hat_real = (pp.g_hat[0] * proof.z[0] + pp.g_hat[1] * proof.z[1]).into_affine();
        Ok(pp.y == y_real && pp.y_hat == y_hat_real)
    }
}
