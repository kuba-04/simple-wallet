use bip38::{Decrypt, Encrypt, Error as Bip38Error};
use bip39::{Error as Bip39Error, Mnemonic};
use bitcoin::bip32::Error as Bip32Error;
use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::string::ToString;

const STORE_DIR: String = "simple-wallet".to_string();

pub struct Wallet {
    secret_key: SecretKey,
}

impl Wallet {
    fn new(secret_key: SecretKey) -> Wallet {
        Wallet { secret_key }
    }

    pub fn generate_recovery_code(entropy_type: &EntropyType) -> Result<Mnemonic, Bip39Error> {
        let entropy = generate_entropy_bytes(entropy_type);
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

    fn decrypt_key(encrypted_key: &str, passphrase: &str) -> Result<SecretKey, Bip38Error> {
        let decrypted = encrypted_key.decrypt(passphrase)?.0;
        SecretKey::from_slice(&decrypted).map_err(|_| Bip38Error::PrvKey)
    }

    pub fn store_secret(
        name: &str,
        encrypted_key: &str,
        overwrite: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key_storage = Self::get_or_create_app_dir(STORE_DIR)?;
        if key_storage.join(name.to_string()).exists() && !overwrite {
            return Err(Box::new(Error::new(
                ErrorKind::AlreadyExists,
                "Key already exists",
            )));
        }
        let _ = Self::create_file(key_storage, name, SecretFile::new(encrypted_key));
        Ok(())
    }

    fn get_or_create_app_dir<T: AsRef<Path>>(
        path: T,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let app_dir = dirs::data_local_dir()
            .map(|pb| pb.join::<T>(path))
            .ok_or("Could not determine local data directory")?;

        if !app_dir.exists() {
            fs::create_dir_all(app_dir.clone())?;
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

    pub fn list_wallets() -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let key_storage = Self::get_or_create_app_dir(STORE_DIR)
            .map_err(|_| Error::new(ErrorKind::Other, "Failed to read the storage"))?;
        Ok(key_storage
            .read_dir()
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
            .collect::<Vec<String>>())
    }

    pub fn load(name: &str, passphrase: &str) -> Result<Wallet, Bip38Error> {
        let key_storage = Self::get_or_create_app_dir(STORE_DIR)
            .map_err(|_| Bip38Error::PrvKey)?
            .join(name.to_string());
        if !key_storage.exists() {
            return Err(Bip38Error::PrvKey);
        }

        let read_key = fs::read_to_string(key_storage).map_err(|_| Bip38Error::PrvKey)?;
        let sk =
            Self::decrypt_key(read_key.as_str(), passphrase).map_err(|_| Bip38Error::PrvKey)?;
        Ok(Wallet::new(sk))
    }

    pub fn generate_address(&self) -> Address {
        let private_key = PrivateKey::new(self.secret_key, NetworkKind::Test);
        let c_pubkey =
            CompressedPublicKey::from_private_key(&Secp256k1::default(), &private_key).unwrap();
        Address::p2wpkh(&c_pubkey, Network::Regtest)
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

#[cfg(test)]
mod test {
    use crate::{EntropyType, Wallet};
    use bip38::Decrypt;
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
        let mnemonic = Mnemonic::parse(
            "village curious time execute enjoy pudding play matter artwork lizard cloth judge",
        );

        let sk = Wallet::generate_private_key(&mnemonic.unwrap());
        assert!(sk.is_ok());
    }

    // #[test] ignore takes too long
    fn encrypt_key() {
        let key_bytes = [
            236, 188, 3, 80, 126, 92, 93, 121, 99, 137, 97, 61, 116, 25, 26, 61, 85, 78, 246, 21,
            173, 231, 225, 164, 155, 129, 184, 229, 67, 37, 73, 61,
        ];
        let sk = SecretKey::from_slice(&key_bytes);
        let passphrase = "passphrase";

        let encrypted = Wallet::encrypt_key(sk.unwrap(), passphrase);
        assert!(encrypted.is_ok());

        let encrypted = encrypted.unwrap();
        let decrypted = encrypted.decrypt(passphrase);
        assert!(decrypted.is_ok());
    }
}
