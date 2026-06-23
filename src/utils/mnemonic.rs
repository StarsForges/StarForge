use anyhow::{anyhow, Context, Result};
use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use stellar_strkey::ed25519::{PrivateKey as StellarPrivateKey, PublicKey as StellarPublicKey};

type HmacSha512 = Hmac<Sha512>;

/// Supported BIP39 mnemonic lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    Words12,
    Words24,
}

impl WordCount {
    pub fn as_usize(self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words24 => 24,
        }
    }
}

/// Generate a new BIP39 mnemonic phrase in English.
pub fn generate_phrase(count: WordCount) -> Result<String> {
    let mnemonic = Mnemonic::generate_in(Language::English, count.as_usize())
        .map_err(|e| anyhow!("Failed to generate mnemonic: {}", e))?;
    Ok(mnemonic.to_string())
}

/// Derive a Stellar keypair from a BIP39 phrase (SEP-0005: `m/44'/148'/account'`).
pub fn keypair_from_phrase(
    phrase: &str,
    bip39_passphrase: &str,
    account_index: u32,
) -> Result<(String, String)> {
    let mnemonic = Mnemonic::parse_in(Language::English, normalize_phrase(phrase))
        .map_err(|e| anyhow!("Invalid recovery phrase: {}", e))?;

    let word_count = mnemonic.word_count();
    if word_count != 12 && word_count != 24 {
        anyhow::bail!(
            "Recovery phrase must be 12 or 24 words (got {}).",
            word_count
        );
    }

    let seed = mnemonic.to_seed(bip39_passphrase);
    let private_key = derive_stellar_private_key(&seed, account_index)?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let verifying_key = signing_key.verifying_key();

    let public_key = StellarPublicKey(verifying_key.to_bytes()).to_string();
    let secret_key = StellarPrivateKey(private_key).to_string();
    Ok((public_key, secret_key))
}

fn normalize_phrase(phrase: &str) -> String {
    phrase.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// SLIP-0010 ed25519 derivation for Stellar path `m/44'/148'/account'`.
fn derive_stellar_private_key(seed: &[u8], account_index: u32) -> Result<[u8; 32]> {
    let (mut key, mut chain) = slip10_ed25519_master(seed)?;
    (key, chain) = slip10_ed25519_child(key, chain, hardened(44))?;
    (key, chain) = slip10_ed25519_child(key, chain, hardened(148))?;
    (key, _) = slip10_ed25519_child(key, chain, hardened(account_index))?;
    Ok(key)
}

fn hardened(index: u32) -> u32 {
    index | 0x8000_0000
}

fn slip10_ed25519_master(seed: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").context("HMAC init failed")?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    split_512(&result)
}

fn slip10_ed25519_child(
    parent_key: [u8; 32],
    parent_chain: [u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32])> {
    if index < 0x8000_0000 {
        anyhow::bail!("Stellar derivation requires hardened path segments");
    }

    let mut mac = HmacSha512::new_from_slice(&parent_chain).context("HMAC init failed")?;
    mac.update(&[0x00]);
    mac.update(&parent_key);
    mac.update(&index.to_be_bytes());
    let result = mac.finalize().into_bytes();
    split_512(&result)
}

fn split_512(bytes: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left.copy_from_slice(&bytes[..32]);
    right.copy_from_slice(&bytes[32..]);
    Ok((left, right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_12_and_24_word_phrases() {
        for count in [WordCount::Words12, WordCount::Words24] {
            let phrase = generate_phrase(count).unwrap();
            let words: Vec<_> = phrase.split_whitespace().collect();
            assert_eq!(words.len(), count.as_usize());
            assert!(Mnemonic::parse_in(Language::English, &phrase).is_ok());
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (pk1, sk1) = keypair_from_phrase(phrase, "", 0).unwrap();
        let (pk2, sk2) = keypair_from_phrase(phrase, "", 0).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
        assert!(pk1.starts_with('G'));
        assert!(sk1.starts_with('S'));
    }

    #[test]
    fn different_accounts_derive_different_keys() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (pk0, _) = keypair_from_phrase(phrase, "", 0).unwrap();
        let (pk1, _) = keypair_from_phrase(phrase, "", 1).unwrap();
        assert_ne!(pk0, pk1);
    }

    #[test]
    fn rejects_invalid_checksum_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(keypair_from_phrase(phrase, "", 0).is_err());
    }

    #[test]
    fn sep0005_derives_all_10_accounts_12_words() {
        let phrase =
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
        let passphrase = "";

        let mut addresses = Vec::new();
        for index in 0..10 {
            let (public_key, secret_key) = keypair_from_phrase(phrase, passphrase, index).unwrap();
            assert!(
                public_key.starts_with('G'),
                "Invalid public key for index {}",
                index
            );
            assert!(
                secret_key.starts_with('S'),
                "Invalid secret key for index {}",
                index
            );
            assert_eq!(
                public_key.len(),
                56,
                "Public key has wrong length for index {}",
                index
            );
            assert_eq!(
                secret_key.len(),
                56,
                "Secret key has wrong length for index {}",
                index
            );
            addresses.push(public_key);
        }

        let mut unique = std::collections::HashSet::new();
        for addr in &addresses {
            assert!(
                unique.insert(addr.clone()),
                "Duplicate address at some index"
            );
        }
        assert_eq!(unique.len(), 10, "All 10 addresses must be unique");
    }

    #[test]
    fn sep0005_derives_all_10_accounts_24_words() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let passphrase = "";

        let mut addresses = Vec::new();
        for index in 0..10 {
            let (public_key, secret_key) = keypair_from_phrase(phrase, passphrase, index).unwrap();
            assert!(
                public_key.starts_with('G'),
                "Invalid public key for index {}",
                index
            );
            assert!(
                secret_key.starts_with('S'),
                "Invalid secret key for index {}",
                index
            );
            assert_eq!(
                public_key.len(),
                56,
                "Public key has wrong length for index {}",
                index
            );
            assert_eq!(
                secret_key.len(),
                56,
                "Secret key has wrong length for index {}",
                index
            );
            addresses.push(public_key);
        }

        let mut unique = std::collections::HashSet::new();
        for addr in &addresses {
            assert!(
                unique.insert(addr.clone()),
                "Duplicate address at some index"
            );
        }
        assert_eq!(unique.len(), 10, "All 10 addresses must be unique");
    }
}
