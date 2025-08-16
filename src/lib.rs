use bip38::{Encrypt, EncryptWif, Error as Bip38Error};
use bip39::{Error as Bip39Error, Mnemonic};
use bitcoin::bip32::Error as Bip32Error;
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{NetworkKind, PrivateKey};
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

    pub fn generate_recovery_code(entropy_type: &EntropyType) -> Result<Mnemonic, Bip39Error> {
        let entropy = generate_entropy_bytes(&entropy_type);
        Mnemonic::from_entropy(&entropy)
    }

    pub fn generate_private_key(mnemonic: &Mnemonic) -> Result<SecretKey, Bip32Error> {
        // 1. generate keys
        let seed = &mnemonic.to_seed("mnemonic");
        let master_key = Xpriv::new_master(NetworkKind::Test, seed)?;
        Ok(master_key.private_key)
    }

    // encrypt
    pub fn encrypt_key(sk: SecretKey, passphrase: &str) -> Result<String, Bip38Error> {
        let private_key = PrivateKey::new(sk, NetworkKind::Test);
        let wif = private_key.to_bytes();
        let ar: [u8; 32] = wif.try_into().unwrap();
        ar.encrypt(passphrase, true)
    }

    fn store_key() {
        todo!()
    }

    fn load() -> Wallet {
        todo!()
    }

    fn generate_address() {

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
    use bip38::Decrypt;
    use crate::{EntropyType, Wallet};
    use bip39::Mnemonic;
    use bitcoin::secp256k1::SecretKey;

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

    #[test]
    fn generate_private_key_from_mnemonic() {
        let mnemonic = Mnemonic::parse("village curious time execute enjoy pudding play matter artwork lizard cloth judge");

        let sk = Wallet::generate_private_key(&mnemonic.unwrap());
        assert!(sk.is_ok());
    }

    // #[test] ignore takes too long
    fn encrypt_key() {
        let key_bytes = [236, 188, 3, 80, 126, 92, 93, 121, 99, 137, 97, 61, 116, 25, 26, 61, 85, 78, 246, 21, 173, 231, 225, 164, 155, 129, 184, 229, 67, 37, 73, 61];
        let sk = SecretKey::from_slice(&key_bytes);
        let passphrase = "passphrase";

        let encrypted  = Wallet::encrypt_key(sk.unwrap(), passphrase);
        assert!(encrypted.is_ok());

        let encrypted = encrypted.unwrap();
        let decrypted = encrypted.decrypt(passphrase);
        assert!(decrypted.is_ok());
    }
}
