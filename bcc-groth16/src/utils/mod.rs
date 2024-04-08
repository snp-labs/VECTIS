use ark_serialize::Read;
use ark_std::vec::Vec;
use std::fs::{self, File};
use std::path::Path;

/// Read Vec<u8> from file
pub fn read_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let mut f = File::open(&path).expect("no file found");
    let metadata = fs::metadata(&path).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}
