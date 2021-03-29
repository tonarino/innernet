use crate::backends;
use std::{ffi::NulError, fmt};

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
#[cfg(not(target_os = "linux"))]
pub use backends::userspace::Key;

#[cfg(target_os = "linux")]
pub use backends::kernel::Key;

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
        let public = private.generate_public();
        KeyPair { private, public }
    }

    pub fn from_private(key: Key) -> Self {
        let public = key.generate_public();
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

        let key = Key::zero();
        assert!(key.is_zero());

        let key = Key::generate_preshared();
        assert!(!key.is_zero());
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
        let pubkey = privkey.generate_public();

        assert_ne!(privkey, pubkey);
    }

    #[test]
    fn test_generate_keypair_helper() {
        use crate::key::KeyPair;
        let pair = KeyPair::generate();

        assert_ne!(pair.private, pair.public);
    }
}
