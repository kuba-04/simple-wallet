use bip39::Mnemonic;
use bitcoin::Address;
use bitcoin::hashes::Hash;
use rand::rngs::OsRng;
use rand::{RngCore, TryRngCore};
use std::path::PathBuf;

pub struct Wallet {
    name: String,
    key_pair: KeyPair,
}

impl Wallet {
    fn new(name: String, key_pair: KeyPair) -> Wallet {
        Wallet { name, key_pair }
    }

    //** Mnemonic::from_entropy() handles the checksum part which could look like below:
    //
    // let hash = sha256::Hash::hash(&entropy);
    // let entropy_with_checksum = match entropy_type {
    //     EntropyType::Bits128 => {
    //         let checksum_4bits = hash[0] >> 4;
    //         let mut result = entropy.to_vec();
    //         let last_byte = (checksum_4bits << 4) | 0;
    //         result.push(last_byte);
    //         result
    //     },
    //     EntropyType::Bits256 => {
    //         let checksum_8bits = hash[0];
    //         let mut result = entropy.to_vec();
    //         result.push(checksum_8bits);
    //         result
    //     },
    // };
    pub fn generate_recovery_code(entropy_type: &EntropyType) -> Option<String> {
        let entropy = generate_entropy_bytes(&entropy_type);
        let mnemonic = Mnemonic::from_entropy(&entropy);
        Some(
            mnemonic
                .unwrap()
                .words()
                .map(|w| w.into())
                .collect::<Vec<String>>()
                .join(" ")
                .to_string(),
        )
    }

    fn generate_address() -> Address {
        todo!()
        // 1. generate keys
        // 2. store them in local file
        // 3. generate address from saved key
        // 4. return address
    }

    fn load() -> Wallet {
        todo!()
    }
}

#[derive(Default)]
pub enum EntropyType {
    Bits128,
    #[default]
    Bits256,
}

fn generate_entropy_bytes(entropy: &EntropyType) -> Vec<u8> {
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

struct KeyPair {
    public: PrivateKey,
    private: PublicKey,
}

struct PrivateKey {
    path: PathBuf,
}

struct PublicKey {
    path: PathBuf,
}

#[cfg(test)]
mod test {
    use crate::{EntropyType, Wallet};
    use bip39::Mnemonic;

    #[test]
    fn mnemonic_from_256bits_generation_roundtrip() {
        let generated_mnemonic = Wallet::generate_recovery_code(&EntropyType::Bits256);
        assert!(generated_mnemonic.is_some());
        let generated_mnemonic = generated_mnemonic.unwrap();

        let parsed_mnemonic = Mnemonic::parse(&generated_mnemonic).unwrap().to_string();
        assert_eq!(generated_mnemonic, parsed_mnemonic);
    }

    #[test]
    fn mnemonic_from_128bits_generation_roundtrip() {
        let generated_mnemonic = Wallet::generate_recovery_code(&EntropyType::Bits128);
        assert!(generated_mnemonic.is_some());
        let generated_mnemonic = generated_mnemonic.unwrap();

        let parsed_mnemonic = Mnemonic::parse(&generated_mnemonic).unwrap().to_string();
        assert_eq!(generated_mnemonic, parsed_mnemonic);
    }
}
