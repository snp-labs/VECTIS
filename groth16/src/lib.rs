mod circuit;
mod commitments;

#[cfg(test)]
mod tests;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref LOG_N: usize = 10;
}
