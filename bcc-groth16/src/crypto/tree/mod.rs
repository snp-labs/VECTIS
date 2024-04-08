use core::{
    iter::Sum,
    ops::{Add, AddAssign, Mul},
};

/// Aggregation tree trait
pub trait AggregationTree<U> {
    /// Node type
    type Node;
    /// Compute root with some challenge tau
    fn compute_root(&self, tau: U) -> Self::Node;
}

impl<T, U> AggregationTree<U> for Vec<T>
where
    T: Clone
        + AddAssign<T>
        + for<'a> Add<&'a T, Output = T>
        + for<'a> Mul<&'a U, Output = T>
        + for<'a> Sum<&'a T>,
    U: Clone + core::ops::Mul<U> + for<'a> core::ops::Mul<&'a U, Output = U>,
{
    type Node = T;
    fn compute_root(&self, tau: U) -> Self::Node {
        let mut cm_list = self.clone();
        let mut ret = cm_list[0].clone();

        let mut nodes = cm_list.len();
        let mut coeff = tau;

        while nodes > 1 {
            let even: T = cm_list.iter().skip(1).step_by(2).sum();
            ret += even * &coeff;

            coeff = coeff.clone() * &coeff;
            nodes >>= 1;
            for i in 0..nodes {
                cm_list[i] = cm_list[i << 1].clone() + &cm_list[(i << 1) + 1];
            }
            cm_list.truncate(nodes);
        }

        ret
    }
}
