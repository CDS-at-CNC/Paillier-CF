use num_bigint::BigUint;

use crate::karatsuba_mul::karatsuba_mul::fast_mul;
use crate::crypto_error::crypto_error::CryptoError;

// ---------------------------------------------------------------------------
// cf_add — Addition homomorphique Catalano-Fiore
//
// Encodage CF d'un message m avec masque r :
//   CF(m, r) = (c0, c1)  où  c0 = m - r mod n,  c1 = Enc_Paillier(r)
//
// Propriété additive :
//   CF(m, r) + CF(m', r') = CF(m+m', r+r')
//
// Calcul :
//   c0_res = (m-r) + (m'-r')  mod n  =  c0 + c0'  mod n   ✓ (plaintexts dans Z_n)
//   c1_res = Enc(r) * Enc(r') mod n² =  c1 * c1'  mod n²  ✓ (homomorphisme Paillier)
//
// CORRECTIONS :
//   1. Suppression de la PublicKey fantôme (g = BigUint::default() = 0).
//      Les paramètres n et n_squared sont passés directement.
//   2. c1_snd est un produit de CHIFFRÉS → modulus = n_squared (pas n).
//      Avant : multiple_precision_mul(c1, c1_p, &pk) utilisait pk.n → FAUX.
//   3. Le double `% &pk.n_squared` (redondant) est supprimé.
//   4. La fonction retourne Result pour propager les erreurs de la multiplication.
// ---------------------------------------------------------------------------
pub fn cf_add(
    ciphert0:  &(BigUint, BigUint),
    ciphert1:  &(BigUint, BigUint),
    n:         &BigUint,
    n_squared: &BigUint,
) -> Result<(BigUint, BigUint), CryptoError> {

    let c0   = &ciphert0.0;   // m  - r  mod n  (plaintext masqué)
    let c1   = &ciphert0.1;   // Enc(r)          (chiffré Paillier dans Z_{n²})

    let c0_p = &ciphert1.0;   // m' - r' mod n
    let c1_p = &ciphert1.1;   // Enc(r')

    // Composante plaintext : addition directe dans Z_n
    let c0_res = (c0 + c0_p) % n;

    // Composante chiffrée : multiplication dans Z_{n²}
    // (homomorphisme additif de Paillier : Enc(r) * Enc(r') = Enc(r + r') mod n²)
    // CORRECTION : modulus = n_squared (les chiffrés vivent dans Z_{n²})
    let c1_res = fast_mul(c1, c1_p, n_squared)?;

    Ok((c0_res, c1_res))
}