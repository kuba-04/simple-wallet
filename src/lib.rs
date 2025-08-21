use rand::rand_core::OsRng;
use rand::TryRngCore;

pub mod wallet;

#[derive(Default)]
pub enum EntropyType {
    Bits128,
    #[default]
    Bits256,
}

pub fn generate_entropy_bytes(entropy: &EntropyType) -> Vec<u8> {
    match entropy {
        EntropyType::Bits128 => {
            let mut e = [0u8; 16];
            OsRng.try_fill_bytes(&mut e).unwrap();
            e.to_vec()
        }
        EntropyType::Bits256 => {
            let mut e = [0u8; 32];
            OsRng.try_fill_bytes(&mut e).unwrap();
            e.to_vec()
        }
    }
}