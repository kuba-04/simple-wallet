use bitcoin_wallet::{EntropyType, Wallet};
use std::hash::Hash;
use std::io;

fn main() {
    println!("WELCOME TO BITCOIN WALLET");
    println!("Step 1: Generate passphrase");
    println!("Choose between: 128 / 256 bits");
    println!("(s) 128 bits");
    println!("(l) 256 bits");
    let mut entropy_type_in = String::new();
    let _ = io::stdin().read_line(&mut entropy_type_in);
    let entropy_type = match entropy_type_in.trim() {
        "s" => EntropyType::Bits128,
        "l" => EntropyType::Bits256,
        _ => {
            println!("Defaulting to 256 bits");
            EntropyType::Bits256
        },
    };

    let mnemonic = Wallet::generate_recovery_code(&entropy_type)
        .expect("Failed to generate recovery code");
    println!("Your recovery word codes:");
    println!("=======================================");
    println!("{}", mnemonic);
    println!("=======================================");
    println!("Please save it if you ever need to restore your private key");

    let sk = Wallet::generate_private_key(&mnemonic);

    println!("Enter your encryption passphrase:");
    let mut passphrase = String::new();
    let _ = io::stdin().read_line(&mut passphrase);

    let key = Wallet::encrypt_key(sk.unwrap(), &passphrase).expect("Failed to encrypt key");
    let store_result = Wallet::store_secret(&key.as_str(), false);
    if store_result.is_err() {
        println!("Wallet already exists. Do you want to overwrite the key? y/n");
        let mut decision = String::new();
        let _ = io::stdin().read_line(&mut decision);
        if decision.to_lowercase().trim() == "y" {
            Wallet::store_secret(&key.as_str(), true).expect("Failed to store private key");
        }
    }

    // private key -> public key
    // let public_key = PublicKey::from_secret_key(&Secp256k1::default(), &master_key.private_key);

    // pubkey SHA-256 hash
    // pubkey hash RIPEMD-160 => 20 bytes
    // segwit address:
    // The P2WPKH address is represented in Bech32 encoding and requires the witness version and the public key hash.
    // The witness version for P2WPKH is 0, followed directly by the 20-byte hash
    // Encode this data into a Bech32 address
    // converting the witness program into a base32 string

}