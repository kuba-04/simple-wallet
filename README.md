# Simple Bitcoin Wallet

A basic implementation of a Bitcoin wallet library in Rust that demonstrates core wallet functionality that walks through mnemonic generation into bitcoin address. The private key is stored locally and is managed by the wallet.

## Features

- **Mnemonic Generation**: Generate BIP39 recovery phrases (128 or 256 bits entropy)
- **Private Key Encryption**: Encrypt private keys using BIP38 encryption
- **Wallet Management**: Create, store, and load encrypted wallets
- **Address Generation**: Generate Bitcoin addresses (currently P2WPKH on Regtest network)
- **Local Storage**: Secure local storage of encrypted wallet files

## Quick Start

### Basic Usage

```rust
use bitcoin_wallet::{EntropyType, wallet::Wallet};

// Generate a new wallet
let mnemonic = Wallet::generate_recovery_code(&EntropyType::Bits256)?;
let encrypted_key = Wallet::generate_and_encrypt_private_key(&mnemonic, "your-passphrase")?;

// Store the key
Wallet::store_secret("my-wallet", &encrypted_key, false)?;

// Load and use the wallet
let wallet = Wallet::load("my-wallet", "your-passphrase")?;
let address = wallet.generate_address();
```

## Demo Application

The demo application (`examples/demo.rs`) provides an interactive CLI that demonstrates:

1. **Wallet Creation**: Generate new wallets with custom entropy
2. **Recovery Phrase**: Display and save BIP39 mnemonic phrases
3. **Wallet Loading**: Load existing wallets from local storage
4. **Address Generation**: Generate Bitcoin addresses for loaded wallets

### Demo Workflow

1. **Create New Wallet**:

   - Choose entropy level (128 or 256 bits)
   - Generate and display recovery phrase
   - Set wallet name and encryption passphrase
   - Store encrypted wallet locally

2. **Load Existing Wallet**:
   - List available wallets
   - Select wallet by name
   - Enter passphrase to decrypt
   - Generate and display Bitcoin address

### Running the Demo

The project includes a demo application that showcases the wallet functionality:

```bash
cargo run --example demo
```

## Dependencies

- `rust-bitcoin`: Core Bitcoin functionality
- `bip39`: Mnemonic generation and validation
- `bip38`: Private key encryption/decryption
- `rand`: Cryptographically secure random number generation
- `dirs`: Cross-platform directory handling

## Current Limitations

This is a demo implementation with the following limitations:

- **Testnet Only**: Currently generates addresses for Regtest network
- **Single Address Type**: Only supports P2WPKH addresses
- **Basic Storage**: Simple file-based storage without advanced security features
- **No Transaction Support**: Cannot send or receive transactions

## TODO: Next Steps

### High Priority
- [ ] **Network Layer**: Direct blockchain communication
- [ ] **Transaction Support**: Implement transaction creation and signing
- [ ] **Multiple Networks**: Allow to select
- [ ] **Address Types**: Add support for P2PKH, P2SH, and other address formats
- [ ] **Balance Checking**: Query blockchain for wallet balance
- [ ] **Transaction History**: Track and display transaction history
- [ ] **Multiple Accounts**: Support for multiple accounts per wallet
- [ ] **Backup/Restore**: Enhanced backup and recovery mechanisms

### Low Priority

- [ ] **GUI Interface**: Web or desktop GUI application
- [ ] **Hardware Wallet Support**: Integration with hardware wallets
- [ ] **Advanced Security**: Multi-signature support, time-locks

## License

MIT