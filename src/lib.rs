use bip39::{Error, Mnemonic};
use bitcoin::hashes::Hash;
use bitcoin::Address;
use rand::rngs::OsRng;
use rand::{RngCore, TryRngCore};
use std::path::PathBuf;
use std::string::ToString;

pub struct Wallet {
    name: String,
    key_pair: StoredKeyPair,
}

impl Wallet {
    fn new(name: String, key_pair: StoredKeyPair) -> Wallet {
        Wallet { name, key_pair }
    }

    pub fn generate_recovery_code(entropy_type: &EntropyType) -> Result<Mnemonic, Error> {
        let entropy = generate_entropy_bytes(&entropy_type);
        Mnemonic::from_entropy(&entropy)
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

struct StoredKeyPair {
    public: StoredPrivateKey,
    private: StoredPublicKey,
}

struct StoredPrivateKey {
    path: PathBuf,
}

struct StoredPublicKey {
    path: PathBuf,
}

#[cfg(test)]
mod test {
    use crate::{EntropyType, Wallet};
    use bip39::Mnemonic;

    #[test]
    fn mnemonic_from_256bits_generation_roundtrip() {
        let generated_mnemonic = Wallet::generate_recovery_code(&EntropyType::Bits256);
        assert!(generated_mnemonic.is_ok());
        let generated_mnemonic = generated_mnemonic.unwrap();

        let parsed_mnemonic = Mnemonic::parse(&generated_mnemonic.to_string()).unwrap();
        assert_eq!(generated_mnemonic, parsed_mnemonic);
    }

    #[test]
    fn mnemonic_from_128bits_generation_roundtrip() {
        let generated_mnemonic = Wallet::generate_recovery_code(&EntropyType::Bits128);
        assert!(generated_mnemonic.is_ok());
        let generated_mnemonic = generated_mnemonic.unwrap();

        let parsed_mnemonic = Mnemonic::parse(&generated_mnemonic.to_string()).unwrap();
        assert_eq!(generated_mnemonic, parsed_mnemonic);

        let seed = generated_mnemonic.to_seed("mnemonic");
        assert_eq!(seed.len(), 64);
    }
}
