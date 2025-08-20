use bip38::{Decrypt, Encrypt, EncryptWif, Error as Bip38Error};
use bip39::{Error as Bip39Error, Mnemonic};
use bitcoin::bip32::Error as Bip32Error;
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{NetworkKind, PrivateKey};
use rand::rngs::OsRng;
use rand::{RngCore, TryRngCore};
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::string::ToString;
use bitcoin::hex::DisplayHex;

pub struct Wallet {
    name: String,
    xpriv: Xpriv,
}

impl Wallet {
    fn new(name: String, xpriv: Xpriv) -> Wallet {
        Wallet { name, xpriv }
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


    pub fn store_secret(name: &str, encrypted_key: &str, overwrite: bool) -> Result<(), Box<dyn std::error::Error>> {
        let key_storage = Self::get_or_create_app_dir("simple-wallet".to_string())?;
        if key_storage.join(name.to_string()).exists() && !overwrite {
            return Err(Box::new(Error::new(ErrorKind::AlreadyExists, "Key already exists")));
        }
        let _ = Self::create_file(
            key_storage,
            name,
            SecretFile::new(encrypted_key)
        );
        Ok(())
    }

    fn get_or_create_app_dir<T: AsRef<Path>>(path: T) -> Result<PathBuf, Box<dyn std::error::Error>> {
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
        let key_storage = Self::get_or_create_app_dir("simple-wallet".to_string())
            .map_err(|e| Error::new(ErrorKind::Other, "Failed to read the storage"))?;
        Ok(key_storage
            .read_dir()
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
            .collect::<Vec<String>>())
    }

    pub fn load(name: &str, passphrase: &str) -> Result<Wallet, Error> {
        let key_storage = Self::get_or_create_app_dir("simple-wallet".to_string())
            .map_err(|e| Error::new(ErrorKind::InvalidFilename, "Failed to read the storage"))?
            .join(name.to_string());
        if !key_storage.exists() {
            return Err(Error::new(ErrorKind::NotFound, "No such wallet created"));
        }

        let read_key = fs::read(key_storage)?;

        let decrypted = String::try_from(read_key).unwrap().decrypt(passphrase).unwrap();
        // todo: WrongExtendedKeyLength(32)
        let xpriv_decoded = Xpriv::decode(decrypted.0.as_slice()).unwrap();

        Ok(Wallet::new(name.to_string(), xpriv_decoded))
    }

    // private key -> public key
    // pubkey SHA-256 hash
    // pubkey hash RIPEMD-160 => 20 bytes
    // segwit address:
    // The P2WPKH address is represented in Bech32 encoding and requires the witness version and the public key hash.
    // The witness version for P2WPKH is 0, followed directly by the 20-byte hash
    // Encode this data into a Bech32 address
    // converting the witness program into a base32 string
    pub fn generate_address(&self) -> PublicKey {
        let pubkey = self.xpriv.private_key.public_key(&Secp256k1::default());

        pubkey


    }
}

struct SecretFile {
    encrypted_key: String,
}

impl SecretFile {
    pub fn new(encrypted_key: &str) -> Self {
        SecretFile { encrypted_key: encrypted_key.to_string() }
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
