extern crate proc_macro;
use proc_macro::{TokenStream, TokenTree};
use quote::quote;
use syn::{parse, parse_macro_input, Data, DeriveInput, Expr, Fields, ItemStruct};
use sha2::{Sha256, Digest};
use heck::ToSnakeCase;


#[proc_macro_derive(TypedAccounts, attributes(account))]
pub fn from_account_metas_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let fields = if let Data::Struct(data_struct) = input.data {
        match data_struct.fields {
            Fields::Named(fields_named) => fields_named.named,
            _ => panic!("FromAccountMetas can only be derived for structs with named fields"),
        }
    } else {
        panic!("FromAccountMetas can only be derived for structs");
    };

    let mut field_checks = Vec::new();
    let mut pubkey_fields = Vec::new();
    let mut assignments = Vec::new();

    // Count the number of fields
    let field_count = fields.len();

    for (field_index, field) in fields.iter().enumerate() {
        let field_name = &field.ident;
        let mut is_mutable = false;
        let mut is_signer = false;

        // Check for #[account(mut)] and #[account(signer)]
        for attr in &field.attrs {
            if attr.path().is_ident("account") {
                // Parse the attribute's nested meta items using `parse_nested_meta`
                attr.parse_nested_meta(|meta| {
                    if let Some(ident) = meta.path.get_ident() {
                        match ident.to_string().as_str() {
                            "mut" => is_mutable = true,
                            "signer" => is_signer = true,
                            _ => panic!("Invalid attribute: {}", ident),
                        }
                    } else {
                        panic!("Invalid attribute format");
                    }
                    Ok(())
                }).unwrap();
            }
        }

        // Generate checks for the AccountMeta fields
        let check_writable = if is_mutable {
            quote! {
                if !account_metas[#field_index].is_writable {
                    return Err(anchor_lang::error::ErrorCode::ConstraintMut.into());
                }
            }
        } else {
            quote! {}
        };

        let check_signer = if is_signer {
            quote! {
                if !account_metas[#field_index].is_signer {
                    return Err(anchor_lang::error::ErrorCode::ConstraintSigner.into());
                }
            }
        } else {
            quote! {}
        };

        // Only add checks if they are non-empty
        if !check_writable.is_empty() || !check_signer.is_empty() {
            field_checks.push(quote! {
                #check_writable
                #check_signer
            });
        }

        pubkey_fields.push(quote! {
            pub #field_name: Pubkey
        });

        assignments.push(quote! {
            #field_name: account_metas[#field_index].pubkey
        });
    }

    // Pass the literal value of `field_count` into the generated code
    let expanded = quote! {
        impl FromAccountMetas for #name {
            fn from_account_metas(account_metas: &[AccountMeta]) -> Result<Self> {
                if account_metas.len() != #field_count {
                    return Err(anchor_lang::error::ErrorCode::ConstraintSigner.into());
                }

                #(#field_checks)*

                Ok(Self {
                    #(#assignments),*  // Ensure no extra commas
                })
            }
        }
    };

    TokenStream::from(expanded)
}


fn parse_instruction_attribute(attr: TokenStream) -> (Option<Vec<u8>>, Option<proc_macro2::TokenStream>) {
    let mut tokens = attr.into_iter();
    let mut discriminator_value = None;
    let mut owner_value = None;

    while let Some(token) = tokens.next() {
        match token {
            // Look for the "discriminator" or "owner" identifier
            TokenTree::Ident(ident) if ident.to_string() == "discriminator" => {
                // Expect '=' next
                if let Some(TokenTree::Punct(punct)) = tokens.next() {
                    if punct.as_char() == '=' {
                        // Now look for the value, which should be in a group (array of literals)
                        if let Some(TokenTree::Group(group)) = tokens.next() {
                            let mut group_tokens = group.stream().into_iter();
                            let mut values = vec![];

                            while let Some(TokenTree::Literal(lit)) = group_tokens.next() {
                                if let Ok(parsed_u8) = lit.to_string().trim_start_matches("0x").parse::<u8>() {
                                    values.push(parsed_u8);
                                }
                            }
                            discriminator_value = Some(values);
                        }
                    }
                }
            }
            TokenTree::Ident(ident) if ident.to_string() == "owner" => {
                // Expect '=' next
                if let Some(TokenTree::Punct(punct)) = tokens.next() {
                    if punct.as_char() == '=' {
                        // Collect all tokens until we hit a comma or another punctuation
                        let mut owner_tokens = TokenStream::new();
                        while let Some(next_token) = tokens.next() {
                            match &next_token {
                                TokenTree::Punct(punct) if punct.as_char() == ',' => break,
                                _ => owner_tokens.extend(Some(next_token)),
                            }
                        }

                        // Parse the accumulated tokens as a `syn::Expr`
                        let owner_path_expr: Expr = parse(owner_tokens.into()).expect("Expected a valid owner expression");
                        owner_value = Some(quote! { #owner_path_expr });
                    }
                }
            }
            _ => {}
        }
    }

    // Output the parsed value
    (discriminator_value, owner_value)
}


#[proc_macro_attribute]
pub fn typed_instruction(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the struct where the attribute is applied
    let input = parse_macro_input!(item as ItemStruct);
    let name = &input.ident;
    let struct_name_snake_case = name.to_string().to_snake_case(); // Convert the struct name to snake_case

    let (discriminator, owner) = parse_instruction_attribute(attr);
    // Parse the attribute for custom discriminator, e.g. `#[typed_instruction(discriminator = "...")]`
    let discriminator = match discriminator {
        Some(d) => quote! { &[#(#d),*] },
        None => {
            let default_discriminator = {
                let mut hasher = Sha256::new();
                hasher.update(format!("global:{}", struct_name_snake_case));
                let result = hasher.finalize();
                result[..8].to_vec() // Truncate to the first 8 bytes
            };
            let bytes: Vec<_> = default_discriminator.iter().map(|byte| quote! { #byte }).collect();
            quote! { &[#(#bytes),*] }
        },
    };

    let owner = match owner {
        Some(o) => quote! {
            impl InstructionOwner for #name {
                fn check_owner(pubkey: &Pubkey) -> Result<()> {
                    match pubkey.eq(&#o) {
                        true => Ok(()),
                        false => Err(anchor_lang::error::ErrorCode::IdlInstructionInvalidProgram.into())
                    }
                }
            }
        },
        None => quote! {
            impl InstructionOwner for #name {
                fn check_owner(pubkey: &Pubkey) -> Result<()> {
                    Ok(())
                }
            }
        },
    };

    // Generate the output with `BorshDeserialize` derive and `VariableDiscriminator` trait implementation
    let expanded = quote! {
        #[derive(BorshDeserialize, Debug)]
        #input

        // Implement the VariableDiscriminator trait
        impl VariableDiscriminator for #name {
            const DISCRIMINATOR: &'static [u8] = #discriminator;
        }

        #owner

        // Implement the try_deserialize function for the struct
        impl DeserializeWithDiscriminator for #name {
            fn try_deserialize(bytes: &[u8]) -> Result<Self> {

                // Check that the byte array is at least as long as the discriminator
                if bytes.len() < Self::DISCRIMINATOR.len() {
                    return Err(anchor_lang::error::ErrorCode::InstructionDidNotDeserialize.into());
                }

                // Check if the discriminator matches
                if &bytes[..Self::DISCRIMINATOR.len()] != Self::DISCRIMINATOR {
                    return Err(anchor_lang::error::ErrorCode::InstructionDidNotDeserialize.into());
                }

                // Deserialize the remaining bytes
                let data = &bytes[Self::DISCRIMINATOR.len()..];
                Self::try_from_slice(data).map_err(|_| anchor_lang::error::ErrorCode::InstructionDidNotDeserialize.into())
            }
        }
    };
    TokenStream::from(expanded)
}


#[proc_macro_derive(FromSignedTransaction)]
pub fn from_signed_transaction_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let fields = if let Data::Struct(data_struct) = input.data {
        match data_struct.fields {
            Fields::Named(fields_named) => fields_named.named,
            _ => panic!("FromAccountMetas can only be derived for structs with named fields"),
        }
    } else {
        panic!("FromAccountMetas can only be derived for structs");
    };

    let mut assignments = Vec::new();

    // Count the number of fields
    let mut field_index = 0usize;

    for field in fields.iter() {
        let field_name = &field.ident;

        if let Some(name) = field_name {
            if ["header", "recent_blockhash"].contains(&name.to_string().as_str()) {
                continue;
            }
        }

        assignments.push(quote! {
            #field_name: TypedInstruction::try_from(&value.instructions[#field_index])?
        });
        field_index += 1;
    }

    // Pass the literal value of `field_count` into the generated code
    let expanded = quote! {
        impl TryFrom<SignedTransaction> for #name {

            type Error = anchor_lang::error::Error;

            fn try_from(value: SignedTransaction) -> Result<#name> {
                Ok(#name {
                    header: value.header,
                    recent_blockhash: value.recent_blockhash,
                    #(#assignments),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}