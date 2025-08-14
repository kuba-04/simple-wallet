use std::hash::Hash;
use bitcoin_wallet::{EntropyType, Wallet};
use std::io;
use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::NetworkKind;
use bitcoin::secp256k1::PublicKey;

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
    println!("Your passphrase:");
    println!("=======================================");
    println!("{}", mnemonic);
    println!("=======================================");
    println!("Please save it if you ever need to restore your private key");


    // todo:
    // generate the seed
    let seed = mnemonic.to_seed("mnemonic");

    // derive private key
    let master_key = Xpriv::new_master(NetworkKind::Test, &seed).expect("Failed to generate master key");

    // private key -> public key
    let public_key = PublicKey::from_secret_key(&Secp256k1::default(), &master_key.private_key);

    // pubkey SHA-256 hash
    // pubkey hash RIPEMD-160 => 20 bytes
    // segwit address:
    // The P2WPKH address is represented in Bech32 encoding and requires the witness version and the public key hash.
    // The witness version for P2WPKH is 0, followed directly by the 20-byte hash
    // Encode this data into a Bech32 address
    // converting the witness program into a base32 string

}