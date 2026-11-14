//! Wallet standard (spec 7, outside consensus): mnemonic, key derivation, Bech32m addresses.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use slh_dsa::{Sha2_128s, SigningKey};
use unicode_normalization::UnicodeNormalization;

use crate::consensus::{Hash, address};

const B32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M: u32 = 0x2BC8_30A3;
pub const HRP: &str = "fb";

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1FF_FFFF) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut n, mut out) = (0u32, 0u32, Vec::new());
    let mask = (1u32 << to) - 1;
    for &v in data {
        acc = ((acc << from) | v as u32) & 0xFF_FFFF;
        n += from;
        while n >= to {
            n -= to;
            out.push(((acc >> n) & mask) as u8);
        }
    }
    if pad {
        if n > 0 {
            out.push(((acc << (to - n)) & mask) as u8);
        }
    } else if n >= from || (acc << (to - n)) & mask != 0 {
        return None;
    }
    Some(out)
}

pub fn encode_address(addr: &Hash) -> String {
    let data = convert_bits(addr, 8, 5, true).unwrap();
    let mut v = hrp_expand(HRP);
    v.extend(&data);
    v.extend([0u8; 6]);
    let pm = polymod(&v) ^ BECH32M;
    let mut s = String::from(HRP);
    s.push('1');
    for d in data {
        s.push(B32[d as usize] as char);
    }
    for i in 0..6 {
        s.push(B32[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

pub fn decode_address(s: &str) -> Option<Hash> {
    if s.to_lowercase() != s && s.to_uppercase() != s {
        return None;
    }
    let s = s.to_lowercase();
    let pos = s.rfind('1')?;
    if &s[..pos] != HRP {
        return None;
    }
    let data: Vec<u8> = s[pos + 1..].bytes().map(|c| B32.iter().position(|&x| x == c).map(|p| p as u8)).collect::<Option<_>>()?;
    let mut v = hrp_expand(HRP);
    v.extend(&data);
    if data.len() < 6 || polymod(&v) != BECH32M {
        return None;
    }
    convert_bits(&data[..data.len() - 6], 5, 8, false)?.try_into().ok()
}

/// Either a `fb1...` address or 64 hex digits of the raw 32-byte address.
pub fn parse_address(s: &str) -> Option<Hash> {
    decode_address(s).or_else(|| crate::consensus::unhex32(s))
}

pub fn seed_from_mnemonic(mnemonic: &str, passphrase: &str) -> [u8; 32] {
    let m: String = mnemonic.nfkd().collect();
    let mut salt = b"fable".to_vec();
    salt.extend(passphrase.nfkd().collect::<String>().bytes());
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(m.as_bytes(), &salt, 2048, &mut out);
    out
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// 48 bytes for SLH-DSA key generation: SK.seed, SK.prf, PK.seed.
pub fn key_seed(seed: &[u8; 32], account: u32, index: u32) -> [u8; 48] {
    let mut path = [0u8; 8];
    path[..4].copy_from_slice(&account.to_le_bytes());
    path[4..].copy_from_slice(&index.to_le_bytes());
    let a = hmac(seed, &[b"fable/0", &path]);
    let b = hmac(seed, &[b"fable/1", &path]);
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(&a);
    out[32..].copy_from_slice(&b[..16]);
    out
}

/// Checks the BIP39 word list and checksum. The seed itself is the PBKDF2 above, not BIP39's.
pub fn check_mnemonic(words: &str) -> Result<(), String> {
    let m = bip39::Mnemonic::parse_normalized(&words.nfkd().collect::<String>()).map_err(|e| e.to_string())?;
    if m.word_count() != 24 {
        return Err(format!("{} words, want 24", m.word_count()));
    }
    Ok(())
}

pub fn new_mnemonic() -> String {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).expect("operating system randomness");
    bip39::Mnemonic::from_entropy(&entropy).unwrap().to_string()
}

pub struct Key {
    pub sk: SigningKey<Sha2_128s>,
    pub pk: [u8; 32],
    pub addr: Hash,
}

impl Key {
    pub fn from_seed48(s: &[u8; 48]) -> Key {
        let sk = SigningKey::<Sha2_128s>::slh_keygen_internal(&s[..16], &s[16..32], &s[32..48]);
        let pk: [u8; 32] = sk.as_ref().to_bytes().as_slice().try_into().unwrap();
        Key { addr: address(&pk), sk, pk }
    }

    pub fn derive(seed: &[u8; 32], account: u32, index: u32) -> Key {
        Key::from_seed48(&key_seed(seed, account, index))
    }

    /// Deterministic signing (no added randomness), pure interface, empty context.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.try_sign_with_context(msg, &[], None).unwrap().to_vec()
    }
}

/// Fill in the witnesses: one per distinct input address, in order of first appearance.
/// `input_addrs[i]` is the address that owns `tx.ins[i]`.
pub fn sign_tx(tx: &mut crate::consensus::Tx, input_addrs: &[Hash], keys: &[&Key], chain_id: &Hash) -> std::result::Result<(), String> {
    let mut want: Vec<Hash> = Vec::new();
    for a in input_addrs {
        if !want.contains(a) {
            want.push(*a);
        }
    }
    let msg = tx.sighash(chain_id);
    tx.wits = want
        .iter()
        .map(|a| {
            let k = keys.iter().find(|k| &k.addr == a).ok_or_else(|| format!("no key for address {}", encode_address(a)))?;
            Ok(crate::consensus::Witness { pk: k.pk, sig: k.sign(&msg) })
        })
        .collect::<std::result::Result<_, String>>()?;
    Ok(())
}
