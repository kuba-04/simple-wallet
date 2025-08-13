use bitcoin_wallet::{EntropyType, Wallet};
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

    let wordlist = Wallet::generate_recovery_code(&entropy_type)
        .expect("Failed to generate recovery code");
    println!("Your passphrase:");
    println!("=======================================");
    println!("{}", wordlist);
    println!("=======================================");
    println!("Please save it if you ever need to restore your private key");
}