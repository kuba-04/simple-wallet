use bip38::{Decrypt, Encrypt};
use bip39::{Error as Bip39Error, Mnemonic};
use bitcoin::bip32::Error as Bip32Error;
use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::string::ToString;
use crate::{generate_entropy_bytes, EntropyType};

const STORE_DIR: &str = "simple-wallet";
const PASSPHRASE: &str = "mnemonic";

pub struct Wallet {
    secret_key: SecretKey,
}

#[derive(Debug)]
pub enum Error {
    IO(String),
    Encryption,
    Decryption,
    Bip32Error,
}

impl Wallet {
    fn new(secret_key: SecretKey) -> Wallet {
        Wallet { secret_key }
    }

    /// First step in wallet creation is to generate the mnemonic, a human-readable code phrases
    /// which can be used to recover the private key
    pub fn generate_recovery_code(entropy_type: &EntropyType) -> Result<Mnemonic, Bip39Error> {
        let entropy = generate_entropy_bytes(entropy_type);
        Mnemonic::from_entropy(&entropy)
    }

    /// Second step is to generate the private key and immediately encrypt it so it is not exposed
    /// anywhere outside
    pub fn generate_and_encrypt_private_key(mnemonic: &Mnemonic, passphrase: &str) -> Result<String, Error> {
        let sk = Self::generate_private_key(mnemonic).map_err(|_| Error::Bip32Error)?;
        Self::encrypt_key(sk, passphrase)
    }

    fn generate_private_key(mnemonic: &Mnemonic) -> Result<SecretKey, Bip32Error> {
        let seed = &mnemonic.to_seed(PASSPHRASE.to_string());
        let master_key = Xpriv::new_master(NetworkKind::Test, seed)?;
        Ok(master_key.private_key)
    }

    fn encrypt_key(sk: SecretKey, passphrase: &str) -> Result<String, Error> {
        let private_key = PrivateKey::new(sk, NetworkKind::Test);
        let wif = private_key.to_bytes();
        let ar: [u8; 32] = wif.try_into().unwrap();
        ar.encrypt(passphrase, true).map_err(|_| Error::Encryption)
    }

    fn decrypt_key(encrypted_key: &str, passphrase: &str) -> Result<SecretKey, Error> {
        let decrypted = encrypted_key.decrypt(passphrase).map_err(|_| Error::Decryption)?.0;
        SecretKey::from_slice(&decrypted).map_err(|_| Error::Decryption)
    }

    /// Third step is to store the encrypted secret locally under the wallet name file
    pub fn store_secret(
        name: &str,
        encrypted_key: &str,
        overwrite: bool,
    ) -> Result<(), Error> {
        let key_storage = Self::get_or_create_app_dir(STORE_DIR.to_string()).map_err(|_| Error::IO("Failed to access dir".to_string()))?;
        if key_storage.join(name.to_string()).exists() && !overwrite {
            return Err(Error::IO("Already exists".to_string()));
        }
        let _ = Self::create_file(key_storage, name, SecretFile::new(encrypted_key));
        Ok(())
    }

    fn get_or_create_app_dir<T: AsRef<Path>>(
        path: T,
    ) -> Result<PathBuf, Error> {
        let app_dir = dirs::data_local_dir()
            .map(|pb| pb.join::<T>(path))
            .ok_or(Error::IO("Could not determine local data directory".to_string()))?;

        if !app_dir.exists() {
            fs::create_dir_all(app_dir.clone()).map_err(|_| Error::IO("Failed to create data directory".to_string()))?;
        }

        Ok(app_dir)
    }

    fn create_file(
        app_dir: PathBuf,
        file_name: &str,
        content: SecretFile,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file_path = app_dir.join(file_name.trim().to_string());
        fs::write(file_path, content.encrypted_key)?;
        Ok(())
    }

    /// List all available wallets on our local system
    pub fn list_wallets() -> Result<Vec<String>, Error> {
        let key_storage = Self::get_or_create_app_dir(STORE_DIR.to_string())
            .map_err(|_| Error::IO("Failed to access the storage".to_string()))?;
        Ok(key_storage
            .read_dir()
            .map_err(|_| Error::IO("Failed to read the storage".to_string()))?
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
            .collect::<Vec<String>>())
    }

    /// Load up the wallet from disc
    pub fn load(name: &str, passphrase: &str) -> Result<Wallet, Error> {
        let key_storage = Self::get_or_create_app_dir(STORE_DIR.to_string())
            .map_err(|_| Error::IO("Failed to access the storage".to_string()))?
            .join(name.to_string());
        if !key_storage.exists() {
            return Err(Error::IO("Storage does not exist".to_string()));
        }

        let read_key = fs::read_to_string(key_storage).map_err(|_| Error::IO("Failed to read the key".to_string()))?;
        let sk =
            Self::decrypt_key(read_key.as_str(), passphrase).map_err(|_| Error::Decryption)?;
        Ok(Wallet::new(sk))
    }

    /// Generate a bitcoin address for the wallet
    pub fn generate_address(&self) -> Address {
        let private_key = PrivateKey::new(self.secret_key, NetworkKind::Test);
        let public_key =
            CompressedPublicKey::from_private_key(&Secp256k1::default(), &private_key).unwrap();
        Address::p2wpkh(&public_key, Network::Regtest)
    }
}

struct SecretFile {
    encrypted_key: String,
}

impl SecretFile {
    pub fn new(encrypted_key: &str) -> Self {
        SecretFile {
            encrypted_key: encrypted_key.to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{EntropyType};
    use bip38::Decrypt;
    use bip39::Mnemonic;
    use bitcoin::secp256k1::SecretKey;
    use super::{Error, Wallet};
    use super::*;

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
        let mnemonic = Mnemonic::parse(
            "village curious time execute enjoy pudding play matter artwork lizard cloth judge",
        );

        let sk = Wallet::generate_private_key(&mnemonic.unwrap());
        assert!(sk.is_ok());
    }

    #[test]
    fn generate_and_encrypt_private_key() {
        let mnemonic = Mnemonic::parse(
            "village curious time execute enjoy pudding play matter artwork lizard cloth judge",
        ).unwrap();
        let passphrase = "passphrase";

        let encrypted_key = Wallet::generate_and_encrypt_private_key(&mnemonic, &passphrase);

        assert!(encrypted_key.is_ok());
    }

}
