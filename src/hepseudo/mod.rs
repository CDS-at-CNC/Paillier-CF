// =============================================================================
// hepseudo — FHEnymisation (deterministic Paillier pseudonymization)
//
// Ported from the v0.4.0 module (`server/src/HEpseudo`). Only the pieces used by
// the PyO3 bindings are kept:
//   - PII TLV encoder (excludes the technical `id` field so two rows of the same
//     patient produce the same pseudonym).
//   - Deterministic Paillier encryption  Enc(m) = g^m mod n²  (no randomness).
//   - Server remask  FE = Enc^b mod n²  with a SINGLE b per batch, so identical
//     patients map to identical pseudonyms within a file.
//
// The secret key is never used here: the FE are the pseudonyms, never decrypted.
// =============================================================================

use num_bigint::{BigUint, RandBigInt};
use rand_core::OsRng;

use crate::crypto_error::crypto_error::CryptoError;
use crate::paillier::p_keygen::PublicKey;

// ----------------------------------------------------------------------------
// TLV tags (the `id` field is intentionally excluded from the stream).
// ----------------------------------------------------------------------------
const TAG_PRENOM: u8 = 0x02;
const TAG_NOM: u8 = 0x03;
const TAG_AGE: u8 = 0x04;
const TAG_DDN: u8 = 0x05;
const TAG_NSS: u8 = 0x06;

/// Structured patient PII.
#[derive(Debug, Clone)]
pub struct PatientPii {
    pub id: String,
    pub prenom: String,
    pub nom: String,
    pub age: u8,
    pub ddn: u16, // days since 1900-01-01
    pub nss: String,
}

// ----------------------------------------------------------------------------
// VLI length encoding (self-delimiting).
// ----------------------------------------------------------------------------
fn encode_vli(len: usize, out: &mut Vec<u8>) -> Result<(), CryptoError> {
    if len < 128 {
        out.push(len as u8);
    } else if len < 16_384 {
        out.push(0x80 | ((len >> 8) as u8));
        out.push((len & 0xFF) as u8);
    } else if len < 2_097_152 {
        out.push(0xC0 | ((len >> 16) as u8));
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        return Err(CryptoError::InvalidInput(format!(
            "VLI: length {} exceeds 2^21 - 1",
            len
        )));
    }
    Ok(())
}

fn tlv_bytes(tag: u8, value: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
    out.push(tag);
    encode_vli(value.len(), out)?;
    out.extend_from_slice(value);
    Ok(())
}

// ----------------------------------------------------------------------------
// Date of birth → days since 1900-01-01 (u16).
// ----------------------------------------------------------------------------
fn days_since_epoch(year: u32, month: u32, day: u32) -> u16 {
    fn julian_day(y: u32, m: u32, d: u32) -> i64 {
        let y = y as i64;
        let m = m as i64;
        let d = d as i64;
        let a = (14 - m) / 12;
        let yy = y + 4800 - a;
        let mm = m + 12 * a - 3;
        d + (153 * mm + 2) / 5 + 365 * yy + yy / 4 - yy / 100 + yy / 400 - 32045
    }

    let epoch = julian_day(1900, 1, 1);
    let target = julian_day(year, month, day);
    let diff = target - epoch;
    if diff < 0 {
        0u16
    } else if diff > 65535 {
        65535u16
    } else {
        diff as u16
    }
}

/// Parse a date of birth. Accepts "YYYY-MM-DD", "DD/MM/YYYY", "DD.MM.YYYY".
pub fn parse_ddn(s: &str) -> Result<u16, CryptoError> {
    let s = s.trim();
    let err = || CryptoError::InvalidInput(format!("invalid date of birth: '{}'", s));

    if s.len() == 10 && s.as_bytes()[4] == b'-' {
        let y: u32 = s[0..4].parse().map_err(|_| err())?;
        let m: u32 = s[5..7].parse().map_err(|_| err())?;
        let d: u32 = s[8..10].parse().map_err(|_| err())?;
        return Ok(days_since_epoch(y, m, d));
    }
    if s.len() == 10 && (s.as_bytes()[2] == b'/' || s.as_bytes()[2] == b'.') {
        let d: u32 = s[0..2].parse().map_err(|_| err())?;
        let m: u32 = s[3..5].parse().map_err(|_| err())?;
        let y: u32 = s[6..10].parse().map_err(|_| err())?;
        return Ok(days_since_epoch(y, m, d));
    }
    Err(err())
}

// ----------------------------------------------------------------------------
// stream(PII) — deterministic TLV serialization (fixed field order).
// `id` is intentionally excluded: only prenom, nom, age, ddn, nss identify a
// patient, so two rows of the same person yield the same pseudonym.
// ----------------------------------------------------------------------------
fn stream(pii: &PatientPii) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::with_capacity(128);
    tlv_bytes(TAG_PRENOM, pii.prenom.as_bytes(), &mut out)?;
    tlv_bytes(TAG_NOM, pii.nom.as_bytes(), &mut out)?;
    tlv_bytes(TAG_AGE, &[pii.age], &mut out)?;
    tlv_bytes(TAG_DDN, &pii.ddn.to_be_bytes(), &mut out)?;
    tlv_bytes(TAG_NSS, pii.nss.as_bytes(), &mut out)?;
    Ok(out)
}

/// encode_pii — f(PII) → m, TLV stream interpreted base-256 little-endian.
pub fn encode_pii(pii: &PatientPii) -> Result<BigUint, CryptoError> {
    let bytes = stream(pii)?;
    Ok(BigUint::from_bytes_le(&bytes))
}

// ----------------------------------------------------------------------------
// Deterministic Paillier primitives (no fresh randomness).
// ----------------------------------------------------------------------------

/// Deterministic Paillier encryption: Enc(m) = g^m mod n².
pub fn p_encrypt_det(m: &BigUint, pk: &PublicKey) -> Result<BigUint, CryptoError> {
    if m >= &pk.n {
        return Err(CryptoError::MessageOutOfRange);
    }
    Ok(pk.g.modpow(m, &pk.n_squared))
}

/// Homomorphic scalar mul: Enc(m)^a = Enc(m·a) mod n².
pub fn he_smul_det(c: &BigUint, a: &BigUint, pk: &PublicKey) -> BigUint {
    c.modpow(a, &pk.n_squared)
}

/// Uniform random value in [1, n).
fn random_nonzero(n: &BigUint) -> BigUint {
    let mut rng = OsRng;
    rng.gen_biguint_range(&BigUint::from(1u32), n)
}

// ----------------------------------------------------------------------------
// Client / server records.
// ----------------------------------------------------------------------------

/// What the client sends to the server for one patient.
#[derive(Debug, Clone)]
pub struct ClientRecord {
    pub enc_m: BigUint,
    pub metier_vals: Vec<String>,
}

/// What the server returns: FE_i = Enc_i^b mod n².
#[derive(Debug, Clone)]
pub struct ServerResponse {
    pub fe: BigUint,
    pub metier_vals: Vec<String>,
}

/// Server remask: draw a single b for the whole batch, then FE_i = Enc_i^b.
/// Same b for every row → identical patients (same Enc_i) produce identical FE_i.
pub fn server_remask(
    records: &[ClientRecord],
    pk: &PublicKey,
) -> Result<Vec<ServerResponse>, CryptoError> {
    let b_session = random_nonzero(&pk.n);
    Ok(records
        .iter()
        .map(|rec| ServerResponse {
            fe: he_smul_det(&rec.enc_m, &b_session, pk),
            metier_vals: rec.metier_vals.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::p_keygen::p_keygen::p_keygen;

    fn pii(id: &str, nom: &str) -> PatientPii {
        PatientPii {
            id: id.to_string(),
            prenom: "Jean".into(),
            nom: nom.into(),
            age: 42,
            ddn: 30_000,
            nss: "1234567890123".into(),
        }
    }

    #[test]
    fn determinism_id_exclusion_and_remask() {
        let kp = p_keygen(512).expect("keygen");
        let pk = &kp.public_key;

        // Same patient, different technical id → same encoded m (id excluded).
        let m_a = encode_pii(&pii("A001", "Dupont")).unwrap();
        let m_b = encode_pii(&pii("B999", "Dupont")).unwrap();
        assert_eq!(m_a, m_b, "id must be excluded from the encoding");

        // Deterministic encryption: same m → same ciphertext.
        let enc_a = p_encrypt_det(&m_a, pk).unwrap();
        let enc_b = p_encrypt_det(&m_b, pk).unwrap();
        assert_eq!(enc_a, enc_b, "deterministic encryption");

        // Different patient → different ciphertext.
        let enc_c = p_encrypt_det(&encode_pii(&pii("C", "Martin")).unwrap(), pk).unwrap();
        assert_ne!(enc_a, enc_c);

        // Remask: single b per batch → same patient = same pseudonym, business cols kept.
        let recs = vec![
            ClientRecord { enc_m: enc_a.clone(), metier_vals: vec!["x".into()] },
            ClientRecord { enc_m: enc_b.clone(), metier_vals: vec!["y".into()] },
            ClientRecord { enc_m: enc_c.clone(), metier_vals: vec!["z".into()] },
        ];
        let resp = server_remask(&recs, pk).unwrap();
        assert_eq!(resp[0].fe, resp[1].fe, "same patient → same pseudonym");
        assert_ne!(resp[0].fe, resp[2].fe, "different patient → different pseudonym");
        assert_eq!(resp[0].metier_vals, vec!["x".to_string()]);
    }
}
