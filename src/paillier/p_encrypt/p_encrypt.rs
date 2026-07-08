use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand_core::OsRng;
use crate::paillier::p_keygen::PublicKey;
use crate::paillier::math::gcd;
use crate::crypto_error::crypto_error::CryptoError;


// ---------------------------------------------------------------------------
// Chiffrement Paillier : c = g^m * r^n  mod n²
//
// Retourne Err(CryptoError::MessageOutOfRange) si m >= n,
// au lieu de crasher le serveur avec assert!.
// ---------------------------------------------------------------------------
pub fn p_encrypt(m: &BigUint, pk: &PublicKey) -> Result<BigUint, CryptoError> {
    // Validation de l'entrée — erreur récupérable, pas de panic
    if m >= &pk.n {
        return Err(CryptoError::MessageOutOfRange);
    }

    let mut rng = OsRng;

    // Choisit r dans Z*_n : gcd(r, n) = 1 (conformité formelle Paillier)
    let r = loop {
        let candidate = rng.gen_biguint_range(&One::one(), &pk.n);
        if gcd(&candidate, &pk.n) == BigUint::one() {
            break candidate;
        }
    };

    // c = g^m * r^n  mod n²
    let g_m = pk.g.modpow(m, &pk.n_squared);
    let r_n = r.modpow(&pk.n, &pk.n_squared);
    let c = (&g_m * &r_n) % &pk.n_squared;

    Ok(c)
}
