use bip39::Mnemonic;
use rand::rngs::OsRng;
use rand::{RngCore, TryRngCore};
use std::path::PathBuf;
use bitcoin::Address;

struct Wallet {
    name: String,
    key_pair: KeyPair
}

impl Wallet {
    fn new(name: String, key_pair: KeyPair) -> Wallet {
        Wallet {
            name,
            key_pair,
        }
    }

    fn generate_recovery_code() -> Option<String> {
        let entropy = get_entropy(Entropy::Bits256);
        let mnemonic = Mnemonic::from_entropy(&entropy);

        Some(mnemonic.unwrap().words().map(|w| w.into()).collect::<Vec<String>>().join(" ").to_string())
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

enum Entropy {
    Bits128,
    Bits256,
}

fn get_entropy(entropy: Entropy) -> Vec<u8> {
    match entropy {
        Entropy::Bits128 => {
            let mut e = [0u8; 16];
            OsRng.try_fill_bytes(&mut e).unwrap();
            e.to_vec()
        },
        Entropy::Bits256 => {
            let mut e = [0u8; 32];
            OsRng.try_fill_bytes(&mut e).unwrap();
            e.to_vec()
        },
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
    use crate::Wallet;
    use bip39::Mnemonic;

    #[test]
    fn mnemonic_generation_roundtrip() {
        let generated_mnemonic = Wallet::generate_recovery_code();
        assert!(generated_mnemonic.is_some());
        let generated_mnemonic = generated_mnemonic.unwrap();

        let parsed_mnemonic = Mnemonic::parse(&generated_mnemonic).unwrap().to_string();
        assert_eq!(generated_mnemonic, parsed_mnemonic);
        // println!("mnemonic: {:?}", &mnemonic);
    }

}