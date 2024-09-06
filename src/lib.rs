#[cfg(feature = "anchor")]
pub mod typed_transaction;
#[cfg(feature = "anchor")]
pub use typed_transaction::*;

#[cfg(feature = "anchor")]
pub mod prelude {
    // Anchor-specific imports
    pub use anchor_lang::prelude::*;
    pub use borsh::BorshDeserialize;
    pub use typed_transaction_macros::{typed_instruction, FromSignedTransaction, TypedAccounts};
    pub use anchor_lang::solana_program::{
        sanitize::SanitizeError,
        serialize_utils::{read_pubkey, read_slice, read_u16},
        sysvar::instructions,
    };
    pub use crate::{
        DeserializeWithDiscriminator, FromAccountMetas, InstructionOwner, SignedInstruction,
        SignedTransaction, TransactionHeader, TypedInstruction, VariableDiscriminator,
    };
}

// If the "anchor" feature is not enabled
#[cfg(not(feature = "anchor"))]
pub mod prelude {
    pub use solana_program::{
        sanitize::SanitizeError,
        serialize_utils::{read_pubkey, read_slice, read_u16},
        sysvar::instructions,
    };
}

// Import the prelude (applies to both configurations)
use prelude::*;

// Additional imports specific to non-anchor builds
#[cfg(not(feature = "anchor"))]
use solana_program::{instruction::AccountMeta, pubkey::Pubkey};

// Common imports
use borsh::BorshDeserialize;
use solana_compact_u16::CompactU16;
use solana_ed25519_instruction::Ed25519Signature;
use std::{collections::BTreeSet, io::Read};


#[derive(Clone, Debug)]
pub struct SignedTransaction {
    pub header: TransactionHeader,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<SignedInstruction>,
}

#[derive(Clone, BorshDeserialize, Debug)]
pub struct TransactionHeader {
    pub signers: u8,
    pub readonly_signers: u8,
    pub readonly: u8,
}

#[derive(Clone, Debug)]
pub struct SignedInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

impl SignedTransaction {
    pub fn from_bytes(data: &[u8]) -> std::io::Result<Self> {
        let mut input = data;

        // Deserialize the Ed25519 signature header and offsets
        let offsets = Ed25519Signature::deserialize(&mut input)?.0;

        let first_offset = offsets.first().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid number of instructions",
        ))?;

        // Use a BTreeSet to collect unique signers
        let signers: BTreeSet<&Pubkey> =
            BTreeSet::from_iter(offsets.iter().map(|o| o.get_signer(data)));

        for offset in &offsets {
            // Ensure all instruction indices are set to u16::MAX (0xffff)
            if offset.signature_instruction_index != u16::MAX
                || offset.public_key_instruction_index != u16::MAX
                || offset.message_instruction_index != u16::MAX
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Instruction indices must be set to u16::MAX (0xffff)",
                ));
            }

            // Ensure all signature offsets refer to the same message offset and size
            if offset.message_data_offset != first_offset.message_data_offset
                || offset.message_data_size != first_offset.message_data_size
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "All signature offsets must refer to the same message data offset and size",
                ));
            }
        }

        // Extract the signed data based on the message_data_offset and message_data_size
        let signed_data = data[first_offset.message_data_offset as usize
            ..(first_offset.message_data_offset + first_offset.message_data_size) as usize]
            .to_vec();

        // Use the signed data for further deserialization
        let mut input = &signed_data[..];

        // Deserialize the transaction header
        let header = TransactionHeader::deserialize(&mut input)?;

        // Deserialize the number of account keys
        let num_keys = CompactU16::deserialize(&mut input)?.0 as usize;

        let mut account_flags = [
            (header.signers - header.readonly_signers) as usize,
            header.readonly_signers as usize,
            num_keys - header.readonly as usize - header.signers as usize,
            header.readonly as usize,
        ];

        if num_keys != account_flags.iter().sum::<usize>() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid number of accounts",
            ));
        }
        let mut tx_accounts = Vec::with_capacity(num_keys);

        for _ in 0..num_keys {
            let pubkey: Pubkey = Pubkey::deserialize(&mut input)?;

            let (is_signer, is_writable) = if account_flags[0] > 0 {
                if !signers.contains(&pubkey) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Missing signer",
                    ));
                }
                account_flags[0] -= 1;
                (true, true)
            } else if account_flags[1] > 0 {
                if !signers.contains(&pubkey) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Missing signer",
                    ));
                }
                account_flags[1] -= 1;
                (true, false)
            } else if account_flags[2] > 0 {
                account_flags[2] -= 1;
                (false, true)
            } else if account_flags[3] > 0 {
                account_flags[3] -= 1;
                (false, false)
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid number of accounts",
                ));
            };

            // Deserialize pubkey directly from input slice
            tx_accounts.push(AccountMeta {
                pubkey,
                is_signer,
                is_writable,
            });
        }

        // Deserialize the recent blockhash
        let recent_blockhash = <[u8; 32]>::deserialize(&mut input)?;

        // Deserialize the number of instructions
        let num_instructions = CompactU16::deserialize(&mut input)?.0 as usize;
        let mut instructions: Vec<SignedInstruction> = Vec::with_capacity(num_instructions);

        // Deserialize each instruction
        for _ in 0..num_instructions {
            // Get the program ID
            let program_id_index = u8::deserialize(&mut input)? as usize;
            let program_id = tx_accounts
                .get(program_id_index)
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid account index",
                ))?
                .pubkey;

            // Get the number of accounts for this instruction
            let ix_num_accounts = CompactU16::deserialize(&mut input)?.0 as usize;
            let mut accounts = Vec::with_capacity(ix_num_accounts);

            // Deserialize each account index for the instruction
            for _ in 0..ix_num_accounts {
                let account_index = u8::deserialize(&mut input)?;
                let account = tx_accounts
                    .get(account_index as usize)
                    .ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid account index",
                    ))?
                    .clone();
                accounts.push(account);
            }

            // Get the instruction data
            let ix_data_length = u8::deserialize(&mut input)? as usize;
            let mut instruction_data = vec![0u8; ix_data_length];
            input.read_exact(&mut instruction_data)?;

            // Create the instruction
            let instruction = SignedInstruction {
                program_id,
                accounts,
                data: instruction_data,
            };
            instructions.push(instruction);
        }

        Ok(Self {
            header,
            recent_blockhash,
            instructions,
        })
    }

    pub fn try_deserialize_transaction(data: &mut &[u8]) -> core::result::Result<Self, SanitizeError> {    
        // Get the current transaction index
        let mut current = (*data).len() - 2;
        let index = read_u16(&mut current, data)? + 1;
    
        // Reset current to 0 to get the number of IXs
        current = 0;
        let num_instructions = read_u16(&mut current, data)?;
    
        // Make sure index is within number of instructions
        if index >= num_instructions {
            return Err(SanitizeError::IndexOutOfBounds);
        }
    
        // index into the instruction byte-offset table.
        current += index as usize * 2;
        let start = read_u16(&mut current, data)?;
    
        current = start as usize;
        let num_accounts = read_u16(&mut current, data)?;
        if num_accounts != 0 {
            return Err(SanitizeError::InvalidValue);
        }

        let program_id = read_pubkey(&mut current, data)?;
        if program_id.ne(&instructions::ID) {
            return Err(SanitizeError::InvalidValue);
        }
        let data_len = read_u16(&mut current, data)?;
        let data = read_slice(&mut current, data, data_len as usize)?;
        Ok(SignedTransaction::from_bytes(&data).map_err(|_| SanitizeError::InvalidValue)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "anchor")]
    use anchor_lang::pubkey;
    #[cfg(not(feature = "anchor"))]
    use solana_program::pubkey;

    #[test]
    fn deserialize() {
        let sigix = [
            0x01, 0x00, 0x10, 0x00, 0xff, 0xff, 0x54, 0x00, 0xff, 0xff, 0x50, 0x00, 0x7b, 0x01,
            0xff, 0xff, 0x94, 0x9b, 0x2c, 0x98, 0xe6, 0x4f, 0xb0, 0x96, 0x1a, 0x44, 0x00, 0xc9,
            0x5d, 0xd6, 0xfb, 0xe9, 0x91, 0xae, 0x7c, 0x7a, 0x12, 0xc5, 0x67, 0x09, 0x86, 0x31,
            0x6f, 0x35, 0x23, 0x4d, 0x3d, 0x82, 0xc5, 0x7d, 0x7f, 0xaa, 0x98, 0xfd, 0xf3, 0xdc,
            0x7b, 0xab, 0xa2, 0xd6, 0x0a, 0xf0, 0xe8, 0x97, 0x7c, 0x5b, 0xbe, 0x98, 0x03, 0x7e,
            0x38, 0xae, 0xa7, 0x35, 0x9f, 0x87, 0xbc, 0xba, 0x20, 0x0f, 0x01, 0x00, 0x05, 0x09,
            0xd2, 0x04, 0xc6, 0xd9, 0x47, 0x57, 0x21, 0xd4, 0xe2, 0x97, 0x1b, 0x56, 0x68, 0x1a,
            0x28, 0x2b, 0x24, 0xad, 0x37, 0x81, 0xbf, 0x7f, 0xfd, 0x33, 0xe5, 0x19, 0x10, 0x7d,
            0x13, 0xef, 0xa1, 0x9c, 0x12, 0x64, 0xd6, 0x2c, 0x9b, 0x73, 0xe8, 0xc9, 0x24, 0xd8,
            0x37, 0xd8, 0x36, 0x21, 0x63, 0xad, 0x20, 0x9e, 0x38, 0x56, 0x14, 0x80, 0x47, 0x7d,
            0xdc, 0x5f, 0x95, 0x86, 0x9c, 0x76, 0x21, 0x60, 0xcc, 0x01, 0x21, 0xa2, 0xb0, 0x81,
            0xea, 0xe8, 0x30, 0x4b, 0x15, 0xc4, 0x2f, 0x4d, 0x69, 0x58, 0x7f, 0xf0, 0x26, 0x63,
            0xc7, 0x6c, 0xa8, 0xb8, 0xc4, 0xb4, 0x47, 0x8f, 0xad, 0x82, 0xd8, 0x06, 0xf1, 0x80,
            0x66, 0x8f, 0xed, 0xe9, 0x52, 0x84, 0x57, 0x4c, 0xc6, 0xf8, 0xa6, 0x76, 0x4c, 0x51,
            0x17, 0x1f, 0x34, 0x3d, 0xc7, 0x4f, 0x3f, 0xdc, 0x20, 0x0f, 0x69, 0x65, 0x81, 0x78,
            0x5f, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32,
            0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7, 0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7,
            0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00, 0xeb, 0x24, 0x67, 0xa8,
            0x33, 0xcc, 0x03, 0xb9, 0xcd, 0xa9, 0xa8, 0x59, 0x8d, 0xe5, 0x0c, 0xfa, 0x32, 0xda,
            0x7e, 0x97, 0x3a, 0x12, 0xb1, 0xff, 0xe5, 0x97, 0x78, 0x6c, 0xc0, 0x29, 0xae, 0x16,
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e, 0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2,
            0x97, 0x88, 0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3, 0x44, 0xd8, 0x06, 0x2e,
            0xa9, 0x40, 0x00, 0x00, 0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x5c, 0x51, 0x21, 0x8c,
            0xc9, 0x4c, 0x3d, 0x4a, 0xf1, 0x7f, 0x58, 0xda, 0xee, 0x08, 0x9b, 0xa1, 0xfd, 0x44,
            0xe3, 0xdb, 0xd9, 0x8a, 0x00, 0x00, 0x00, 0x00, 0xc6, 0x58, 0x02, 0x06, 0x95, 0x3c,
            0xb3, 0xaa, 0x4d, 0x8d, 0x4b, 0xd6, 0xd4, 0x28, 0xa3, 0xe8, 0xe3, 0xc2, 0xcc, 0x6f,
            0x26, 0xa2, 0xa9, 0x15, 0xfe, 0xcb, 0xcc, 0x1f, 0xf0, 0xf1, 0x1b, 0x49, 0x03, 0x05,
            0x00, 0x09, 0x03, 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05,
            0x02, 0x40, 0x42, 0x0f, 0x00, 0x06, 0x07, 0x00, 0x02, 0x03, 0x01, 0x04, 0x07, 0x08,
            0x18, 0xf6, 0x96, 0xec, 0xce, 0x6c, 0x3f, 0x3a, 0x0a, 0x64, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let transaction = SignedTransaction::from_bytes(&sigix).unwrap();

        assert_eq!(transaction.instructions.len(), 3);
        assert_eq!(
            transaction.instructions[0].program_id,
            pubkey!("ComputeBudget111111111111111111111111111111")
        );
        assert!(transaction.instructions[0].accounts.is_empty());
        assert_eq!(
            transaction.instructions[1].program_id,
            pubkey!("ComputeBudget111111111111111111111111111111")
        );
        assert!(transaction.instructions[1].accounts.is_empty());
        assert_eq!(
            transaction.instructions[2].accounts[0].pubkey,
            pubkey!("F8pqnWWBZKyTAZgxNNRGLVCkBqf6pbJvvPY38trMr7cF")
        );
        assert!(transaction.instructions[2].accounts[0].is_signer);
        assert_eq!(
            transaction.instructions[2].program_id,
            pubkey!("Gpu1L3Z6tHE6o1ksaBTASLNB4oUkoQe2qzQHqenK8bWd")
        );
        assert_eq!(transaction.instructions[2].accounts.len(), 7);
    }
}
