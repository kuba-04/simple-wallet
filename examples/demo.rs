use bitcoin_wallet::{EntropyType};
use std::io;
use std::process::exit;
use bitcoin_wallet::wallet::{Wallet};

fn main() {
    println!("=====================");
    println!("SIMPLE BITCOIN WALLET");
    println!("=====================");

    let mut wallet_name = String::from("wallet");

    println!("[l] -> load existing wallet");
    println!("[n] -> create new wallet");
    let mut start_option = String::new();
    let _ = io::stdin().read_line(&mut start_option);
    if start_option.trim() == "n" {
        wallet_name = generate_new().expect("Failed to generate new wallet");
        println!("Created new wallet: {}", wallet_name);
        println!("Now loading it up")
    } else if start_option.trim() == "l" {
        println!("Your wallets:");
        let wallets = Wallet::list_wallets().expect("Should list wallets");
        let _ = &wallets.iter().for_each(|w| println!("-> {w}"));
        println!();
        println!("Type wallet name:");
        loop {
            let mut new_wallet_name = String::new();
            let _ = io::stdin().read_line(&mut new_wallet_name);
            if !wallets.contains(&new_wallet_name.trim().to_string()) {
                println!("unmatched..");
                continue;
            }
            wallet_name = new_wallet_name.trim().to_string();
            break;
        }
    } else {
        eprintln!("no such option");
    }

    println!("Enter the passphrase:");
    let mut passphrase = String::new();
    let _ = io::stdin().read_line(&mut passphrase);
    let wallet = Wallet::load(wallet_name.as_str(), &passphrase).expect("Error loading wallet");
    let address = wallet.generate_address();

    println!("Your bitcoin address: {:?}", address);
}

fn generate_new() -> Option<String> {
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
        }
    };

    let mnemonic =
        Wallet::generate_recovery_code(&entropy_type).expect("Failed to generate recovery code");
    println!("Your recovery word codes:");
    println!("=======================================");
    println!("{}", mnemonic);
    println!("=======================================");
    println!("Please save it if you ever need to restore your private key");

    println!("Enter your wallet name:");
    let mut wallet_name = String::new();
    let _ = io::stdin().read_line(&mut wallet_name);

    println!("Enter your encryption passphrase:");
    let mut passphrase = String::new();
    let _ = io::stdin().read_line(&mut passphrase);

    println!("Encrypting...");
    let key = Wallet::generate_and_encrypt_private_key(&mnemonic, &passphrase);
    let key = match key {
        Ok(x) => x,
        Err(_) => {
            println!("Failed to generate private key. Exiting...");
            exit(1);
        },
    };

    println!("Saving...");
    let store_result = Wallet::store_secret(&wallet_name, &key.as_str(), false);
    if store_result.is_err() {
        println!("Wallet already exists. Do you want to overwrite the key? y/n");
        let mut decision = String::new();
        let _ = io::stdin().read_line(&mut decision);
        if decision.to_lowercase().trim() == "y" {
            let result = Wallet::store_secret(&wallet_name, &key.as_str(), true);
            if result.is_ok() {
                println!("Successfully stored the key");
                Some(wallet_name.trim().to_string())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        println!("Done!");
        Some(wallet_name.trim().to_string())
    }
}
