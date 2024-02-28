use num_bigint::BigUint;
use std::fs::File;
use std::io::{BufRead, BufReader, Error, Read};
use std::path::Path;
use std::str::FromStr;

struct Message {
    reciever: PublicRSAKey,
    encrypted_part: Vec<BigUint>,
}

// Max size 1024bit
pub struct EncryptAbleMessage {
    sender: PublicRSAKey,
    text: String,
}

impl EncryptAbleMessage {
    pub fn new(sender: PublicRSAKey, text: String) -> Self {
        Self { sender, text }
    }
    pub fn encrypt(self, key: PublicRSAKey) -> Vec<BigUint> {
        let text = self.text + &self.sender.to_string();
        let text_as_bytes = text.bytes();
        // 128 bytes per chunk
        let mut chunks: Vec<BigUint> = Vec::new();

        let mut vec_b = Vec::new();
        for c in text_as_bytes.enumerate() {
            vec_b.push(c.1);

            if c.0 % 128 == 0 && c.0 > 0 {
                let bi = BigUint::from_bytes_le(&vec_b);
                chunks.push(bi);
                vec_b = Vec::new();
            }
        }

        let mut encrypted_chunks = Vec::new();
        for c in chunks {
            encrypted_chunks.push(rsa_encrypt_biguint(&key, c))
        }

        return encrypted_chunks;
    }
}

pub fn rsa_encrypt_biguint(public_key: &PublicRSAKey, plaintext: BigUint) -> BigUint {
    plaintext.modpow(&public_key.public_e, &public_key.public_n)
}

impl PrivateRSAKey {
    pub fn new(private_phi_n: BigUint, private_d: BigUint) -> Self {
        Self {
            private_phi_n,
            private_d,
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let parts: Vec<&str> = contents.split(',').collect();
        let private_phi_n = BigUint::parse_bytes(parts[0].as_bytes(), 10).unwrap();
        let private_d = BigUint::parse_bytes(parts[1].as_bytes(), 10).unwrap();

        Ok(Self::new(private_phi_n, private_d))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RsaKey {
    pub public: PublicRSAKey,
    pub private: PrivateRSAKey,
}

impl RsaKey {
    pub fn new(public: PublicRSAKey, private: PrivateRSAKey) -> Self {
        Self { public, private }
    }

    pub fn from_files(public_key_file: &Path, private_key_file: &Path) -> Result<Self, Error> {
        let public_key = PublicRSAKey::from_file(public_key_file)?;
        let private_key = PrivateRSAKey::from_file(private_key_file)?;
        Ok(Self::new(public_key, private_key))
    }
}
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PublicRSAKey {
    pub public_n: BigUint,
    pub public_e: BigUint,
}
impl PublicRSAKey {
    pub fn new(public_n: BigUint, public_e: BigUint) -> Self {
        Self { public_n, public_e }
    }

    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let parts: Vec<&str> = contents.split(',').collect();
        let public_n = BigUint::parse_bytes(parts[0].as_bytes(), 10).unwrap();
        let public_e = BigUint::parse_bytes(parts[1].as_bytes(), 10).unwrap();

        Ok(Self::new(public_n, public_e))
    }
    fn to_string(self) -> String {
        let n = self.public_n.to_string();
        let e = self.public_e.to_string();
        return n + "," + &e;
    }
    pub fn from_string(s: String) -> Result<PublicRSAKey, RsaError> {
        let mut p = s.split(",");
        let Some(n) = p.next() else {
            return Err(RsaError::new());
        };
        let Some(e) = p.next() else {
            return Err(RsaError::new());
        };

        let Ok(n) = BigUint::from_str(n) else {
            return Err(RsaError::new());
        };
        let Ok(e) = BigUint::from_str(e) else {
            return Err(RsaError::new());
        };

        return Ok(PublicRSAKey {
            public_e: e,
            public_n: n,
        });
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PrivateRSAKey {
    pub private_phi_n: BigUint,
    pub private_d: BigUint,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RsaError;

impl RsaError {
    pub fn new() -> RsaError {
        return RsaError;
    }
}

impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Oh no, something bad went down")
    }
}

impl std::error::Error for RsaError {}

pub fn rsa_encrypt_simple(plaintext: BigUint, public_key: &PublicRSAKey) -> BigUint {
    return plaintext.modpow(&public_key.public_e, &public_key.public_n);
}

pub fn rsa_decrypt_simple(
    ciphertext: BigUint,
    private_key: &PrivateRSAKey,
    public_key: &PublicRSAKey,
) -> BigUint {
    return ciphertext.modpow(&private_key.private_d, &public_key.public_n);
}
