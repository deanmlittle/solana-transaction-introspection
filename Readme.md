# Solana Signed Transaction Deserialization

Deserialize signed Solana transactions into instructions, signers and blockhash from Ed25519Instruction data for use in payment channels and other L2 settlement scenarios.

## Features

- **Deserialize Transactions onchain**: Deserialize Ed25519Instruction data into a `SignedTransaction`
- **Return signers**: List signers of Ed25519Instruction to validate in your program

## Data Structures

### `SignedTransaction`
A struct representing the signed transaction, containing the following fields:

- `header`: A `SignedTransactionHeader` including the number of signers and readonly accounts.
- `signers`: A vector of unique public keys representing the signers of the transaction.
- `recent_blockhash`: The blockhash at the time the transaction was created.
- `instructions`: A vector of `SignedTransactionInstruction` structs representing the transaction's instructions.

### `SignedTransactionHeader`
A struct that holds metadata about the transaction:

- `signers`: Number of writable signers.
- `readonly_signers`: Number of readonly signers.
- `readonly`: Number of readonly accounts.

### `SignedTransactionInstruction`
A struct representing a single instruction in the transaction:

- `program_id`: The program ID associated with this instruction.
- `accounts`: A vector of public keys representing the accounts involved in the instruction.
- `data`: A vector of bytes representing the instruction data.

## Usage

To deserialize a signed transaction from bytes:

```rust
use solana_program::pubkey;
use solana_signer_transaction::SignedTransaction;

fn main() {
    let transaction_bytes = [/* Ed25519Instruction data */];
    let transaction = SignedTransaction::from_bytes(&transaction_bytes).unwrap();

    // Access transaction components
    println!("{:?}", transaction.signers);
    println!("{:?}", transaction.recent_blockhash);
    println!("{:?}", transaction.instructions);
}
```

## Testing

Unit tests are included to verify the correctness of deserialization.

### Running Tests

```sh
cargo test
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.