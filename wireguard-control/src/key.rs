use std::{ffi::NulError, fmt};

use x25519_dalek::{PublicKey, StaticSecret};

/// Represents an error in base64 key parsing.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct InvalidKey;

impl std::error::Error for InvalidKey {}

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid key format")
    }
}

impl From<NulError> for InvalidKey {
    fn from(_: NulError) -> Self {
        InvalidKey {}
    }
}

/// Represents a WireGuard encryption key.
///
/// WireGuard makes no meaningful distinction between public,
/// private and preshared keys - any sequence of 32 bytes
/// can be used as either of those.
///
/// This means that you need to be careful when working with
/// `Key`s, especially ones created from external data.
#[derive(PartialEq, Eq, Clone, Hash)]
pub struct Key(pub [u8; 32]);

impl Key {
    /// Generates and returns a new private key.
    pub fn generate_private() -> Self {
        use rand_core::{OsRng, RngCore};

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);

        // Apply key clamping.
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        Self(bytes)
    }

    /// Generates and returns a new preshared key.
    #[must_use]
    pub fn generate_preshared() -> Self {
        use rand_core::{OsRng, RngCore};

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Generates a public key for this private key.
    #[must_use]
    pub fn get_public(&self) -> Self {
        let secret = StaticSecret::from(self.0);
        let public = PublicKey::from(&secret);

        Self(public.to_bytes())
    }

    /// Generates an all-zero key.
    #[must_use]
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Converts the key to a standardized base64 representation, as used by the `wg` utility and `wg-quick`.
    pub fn to_base64(&self) -> String {
        base64::encode(self.0)
    }

    /// Converts a base64 representation of the key to the raw bytes.
    ///
    /// This can fail, as not all text input is valid base64 - in this case
    /// `Err(InvalidKey)` is returned.
    pub fn from_base64(key: &str) -> Result<Self, crate::InvalidKey> {
        let mut key_bytes = [0u8; 32];
        let decoded_bytes = base64::decode(key).map_err(|_| InvalidKey)?;

        if decoded_bytes.len() != 32 {
            return Err(InvalidKey);
        }

        key_bytes.copy_from_slice(&decoded_bytes[..]);
        Ok(Self(key_bytes))
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, crate::InvalidKey> {
        let mut sized_bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut sized_bytes).map_err(|_| InvalidKey)?;
        Ok(Self(sized_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pubkey_generation() {
        let privkey = "SGb+ojrRNDuMePufwtIYhXzA//k6wF3R21tEBgKlzlM=";
        let pubkey = "DD5yKRfzExcV5+kDnTroDgCU15latdMjiQ59j1hEuk8=";

        let private = Key::from_base64(privkey).unwrap();
        let public = Key::get_public(&private);

        assert_eq!(public.to_base64(), pubkey);
    }

    #[test]
    fn test_rng_sanity_private() {
        let first = Key::generate_private();
        assert!(first.as_bytes() != [0u8; 32]);
        for _ in 0..100_000 {
            let key = Key::generate_private();
            assert!(first != key);
            assert!(key.as_bytes() != [0u8; 32]);
        }
    }

    #[test]
    fn test_rng_sanity_preshared() {
        let first = Key::generate_preshared();
        assert!(first.as_bytes() != [0u8; 32]);
        for _ in 0..100_000 {
            let key = Key::generate_preshared();
            assert!(first != key);
            assert!(key.as_bytes() != [0u8; 32]);
        }
    }
}

/// Represents a pair of private and public keys.
///
/// This struct is here for convenience of generating
/// a complete keypair, e.g. for a new peer.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyPair {
    /// The private key.
    pub private: Key,
    /// The public key.
    pub public: Key,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key(\"{}\")", self.to_base64())
    }
}

impl KeyPair {
    pub fn generate() -> Self {
        let private = Key::generate_private();
        let public = private.get_public();
        KeyPair { private, public }
    }

    pub fn from_private(key: Key) -> Self {
        let public = key.get_public();
        KeyPair {
            private: key,
            public,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_key_zero() {
        use crate::key::Key;

        let key = Key::generate_preshared();
        assert_ne!(key.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_key_base64() {
        use crate::key::Key;

        let key = Key::generate_preshared();
        let key_b64 = key.to_base64();
        let key_new = Key::from_base64(&key_b64).unwrap();

        assert_eq!(key, key_new);
    }

    #[test]
    fn test_invalid_key() {
        use crate::key::{InvalidKey, Key};

        let key_b64: String = Key::generate_preshared()
            .to_base64()
            .chars()
            .rev()
            .collect();

        assert_eq!(Key::from_base64(&key_b64), Err(InvalidKey));
    }

    #[test]
    fn test_generate_keypair_basic() {
        use crate::key::Key;

        let privkey = Key::generate_private();
        let pubkey = privkey.get_public();

        assert_ne!(privkey, pubkey);
    }

    #[test]
    fn test_generate_keypair_helper() {
        use crate::key::KeyPair;
        let pair = KeyPair::generate();

        assert_ne!(pair.private, pair.public);
    }
}
