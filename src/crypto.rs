use std::num::NonZeroU32;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    digest::{SHA256, digest},
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const KEYSTORE_VERSION: u8 = 1;
const PBKDF2_ITERATIONS: u32 = 210_000;
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    pub version: u8,
    pub address: String,
    pub public_key: String,
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn generate_keyfile(password: &str) -> Result<EncryptedKeyFile> {
    let rng = SystemRandom::new();
    let document = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| Error::Crypto("could not generate Ed25519 key"))?;
    encrypt_key(document.as_ref(), password)
}

pub fn validate_keystore_password(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(Error::msg(
            "keystore password must contain at least 8 characters",
        ));
    }
    Ok(())
}

pub fn encrypt_key(pkcs8: &[u8], password: &str) -> Result<EncryptedKeyFile> {
    validate_keystore_password(password)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8)
        .map_err(|_| Error::Crypto("invalid Ed25519 PKCS#8 key"))?;
    let public_key = key_pair.public_key().as_ref();
    let address = address_from_public_key(public_key);
    let rng = SystemRandom::new();
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    rng.fill(&mut salt)
        .map_err(|_| Error::Crypto("could not generate keystore salt"))?;
    rng.fill(&mut nonce)
        .map_err(|_| Error::Crypto("could not generate keystore nonce"))?;
    let key_bytes = derive_encryption_key(password, &salt, PBKDF2_ITERATIONS)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| Error::Crypto("could not initialize AES-256-GCM"))?;
    let key = LessSafeKey::new(unbound);
    let aad_text = format!("mrk-keystore-v1:{address}");
    let mut ciphertext = pkcs8.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad_text.as_bytes()),
        &mut ciphertext,
    )
    .map_err(|_| Error::Crypto("could not encrypt keystore"))?;
    Ok(EncryptedKeyFile {
        version: KEYSTORE_VERSION,
        address,
        public_key: STANDARD.encode(public_key),
        kdf: "PBKDF2-HMAC-SHA256".to_owned(),
        iterations: PBKDF2_ITERATIONS,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt_key(keyfile: &EncryptedKeyFile, password: &str) -> Result<Ed25519KeyPair> {
    if keyfile.version != KEYSTORE_VERSION || keyfile.kdf != "PBKDF2-HMAC-SHA256" {
        return Err(Error::msg("unsupported keystore format"));
    }
    let salt = decode_sized::<16>(&keyfile.salt, "salt")?;
    let nonce = decode_sized::<12>(&keyfile.nonce, "nonce")?;
    let key_bytes = derive_encryption_key(password, &salt, keyfile.iterations)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| Error::Crypto("could not initialize AES-256-GCM"))?;
    let key = LessSafeKey::new(unbound);
    let aad_text = format!("mrk-keystore-v1:{}", keyfile.address);
    let mut ciphertext = STANDARD
        .decode(&keyfile.ciphertext)
        .map_err(|_| Error::msg("keystore ciphertext is not valid base64"))?;
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad_text.as_bytes()),
            &mut ciphertext,
        )
        .map_err(|_| Error::msg("invalid keystore password or corrupted keyfile"))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(plaintext)
        .map_err(|_| Error::Crypto("decrypted keystore is not a valid Ed25519 key"))?;
    if address_from_public_key(key_pair.public_key().as_ref()) != keyfile.address {
        return Err(Error::Crypto("keystore public address mismatch"));
    }
    Ok(key_pair)
}

fn derive_encryption_key(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; 32]> {
    let iterations = NonZeroU32::new(iterations)
        .ok_or_else(|| Error::msg("keystore PBKDF2 iteration count cannot be zero"))?;
    let mut key = [0_u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        &mut key,
    );
    Ok(key)
}

fn decode_sized<const N: usize>(input: &str, label: &str) -> Result<[u8; N]> {
    let bytes = STANDARD
        .decode(input)
        .map_err(|_| Error::msg(format!("keystore {label} is not valid base64")))?;
    bytes
        .try_into()
        .map_err(|_| Error::msg(format!("keystore {label} has the wrong length")))
}

pub fn address_from_public_key(public_key: &[u8]) -> String {
    let hash = digest(&SHA256, public_key);
    let mut data = vec![1_u8];
    data.extend(convert_bits(&hash.as_ref()[..20], 8, 5, true).expect("fixed conversion"));
    bech32m_encode("mrk", &data)
}

pub fn validate_address(address: &str) -> Result<()> {
    let (hrp, data) = bech32m_decode(address)?;
    if hrp != "mrk" || data.first() != Some(&1) {
        return Err(Error::msg("address is not an MRK v1 address"));
    }
    let decoded = convert_bits(&data[1..], 5, 8, false)?;
    if decoded.len() != 20 {
        return Err(Error::msg("MRK address payload has the wrong length"));
    }
    Ok(())
}

pub fn sign_bytes(key_pair: &Ed25519KeyPair, bytes: &[u8]) -> String {
    STANDARD.encode(key_pair.sign(bytes).as_ref())
}

pub fn verify_bytes(public_key_base64: &str, bytes: &[u8], signature_base64: &str) -> Result<()> {
    let public_key = STANDARD
        .decode(public_key_base64)
        .map_err(|_| Error::msg("public key is not valid base64"))?;
    let signature = STANDARD
        .decode(signature_base64)
        .map_err(|_| Error::msg("signature is not valid base64"))?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(bytes, &signature)
        .map_err(|_| Error::Crypto("signature verification failed"))
}

pub fn sha256_id(prefix: &str, bytes: &[u8]) -> String {
    let hash = digest(&SHA256, bytes);
    format!("{prefix}_{}", hex_lower(&hash.as_ref()[..16]))
}

pub fn sha256_full_id(prefix: &str, bytes: &[u8]) -> String {
    let hash = digest(&SHA256, bytes);
    format!("{prefix}_{}", hex_lower(hash.as_ref()))
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Crypto("could not generate random bytes"))?;
    Ok(bytes)
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0_u8; 6]);
    let polymod = polymod(&values) ^ BECH32M_CONST;
    let mut output = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    output.push_str(hrp);
    output.push('1');
    for value in data {
        output.push(CHARSET[*value as usize] as char);
    }
    for position in 0..6 {
        let shift = 5 * (5 - position);
        output.push(CHARSET[((polymod >> shift) & 31) as usize] as char);
    }
    output
}

fn bech32m_decode(value: &str) -> Result<(String, Vec<u8>)> {
    if value.len() < 8 || value.len() > 90 {
        return Err(Error::msg("invalid MRK address length"));
    }
    if value.chars().any(char::is_uppercase) {
        return Err(Error::msg("MRK addresses must use lowercase characters"));
    }
    let separator = value
        .rfind('1')
        .ok_or_else(|| Error::msg("MRK address is missing its separator"))?;
    if separator == 0 || separator + 7 > value.len() {
        return Err(Error::msg("invalid MRK address structure"));
    }
    let hrp = value[..separator].to_owned();
    let mut values = Vec::with_capacity(value.len() - separator - 1);
    for byte in value[separator + 1..].bytes() {
        let index = CHARSET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or_else(|| Error::msg("MRK address contains an invalid character"))?;
        values.push(index as u8);
    }
    let mut checksum_values = hrp_expand(&hrp);
    checksum_values.extend_from_slice(&values);
    if polymod(&checksum_values) != BECH32M_CONST {
        return Err(Error::msg("MRK address checksum is invalid"));
    }
    values.truncate(values.len() - 6);
    Ok((hrp, values))
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut values = hrp.bytes().map(|byte| byte >> 5).collect::<Vec<_>>();
    values.push(0);
    values.extend(hrp.bytes().map(|byte| byte & 31));
    values
}

fn polymod(values: &[u8]) -> u32 {
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in GENERATORS.iter().enumerate() {
            if ((top >> index) & 1) != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>> {
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let max_value = (1_u32 << to) - 1;
    let mut output = Vec::new();
    for value in data {
        if u32::from(*value) >> from != 0 {
            return Err(Error::msg("invalid address data"));
        }
        accumulator = (accumulator << from) | u32::from(*value);
        bits += from;
        while bits >= to {
            bits -= to;
            output.push(((accumulator >> bits) & max_value) as u8);
        }
    }
    if pad {
        if bits > 0 {
            output.push(((accumulator << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & max_value) != 0 {
        return Err(Error::msg("invalid address padding"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_key_round_trip_and_address_checksum() {
        let keyfile = generate_keyfile("correct horse battery staple").unwrap();
        validate_address(&keyfile.address).unwrap();
        let key = decrypt_key(&keyfile, "correct horse battery staple").unwrap();
        assert_eq!(
            address_from_public_key(key.public_key().as_ref()),
            keyfile.address
        );
        assert!(decrypt_key(&keyfile, "wrong password").is_err());
        let mut broken = keyfile.address.clone().into_bytes();
        let last = broken.len() - 1;
        broken[last] = if broken[last] == b'q' { b'p' } else { b'q' };
        assert!(validate_address(std::str::from_utf8(&broken).unwrap()).is_err());
    }
}
