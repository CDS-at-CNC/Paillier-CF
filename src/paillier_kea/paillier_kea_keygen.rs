use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand_core::OsRng;
use crate::paillier::p_keygen::PublicKey;
use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use crate::crypto_error::crypto_error::CryptoError;

// ============================================================================
// Paire de clés KEA (schéma P^(2), section 6.2 du papier)
//
// Seul psy (ξ) est secret. ct_delta et pk sont publics.
//
// Zeroization manuelle via Drop :
//   BigUint n'implémente pas le trait Zeroize de la crate zeroize.
//   On implémente Drop manuellement pour écraser psy avec zéro
//   au moment de la destruction. ct_delta et pk ne contiennent pas
//   de données secrètes — leur effacement est inoffensif mais on
//   cible uniquement psy pour la clarté.
// ============================================================================
#[derive(Clone, Debug)]
pub struct KeyPairKEA {
    /// Clé Paillier publique associée
    pub pk: PublicKey,
    /// ct_delta = (P.Enc(1), P.Enc(ξ)) — public, publié avec la clé KEA
    pub ct_delta: (BigUint, BigUint),
    /// ξ secret — zeroisé à la destruction via Drop
    pub psy: BigUint,
}

impl Drop for KeyPairKEA {
    fn drop(&mut self) {
        // Écrase psy (ξ) avec zéro avant libération mémoire.
        // BigUint::from(0u32) réassigne le buffer existant,
        // ce qui garantit l'effacement des anciens octets en place.
        self.psy = BigUint::from(0u32);
    }
}

// ============================================================================
// Génération d'une paire de clés KEA
// ============================================================================
pub fn paillier_kea_keygen(pk: &PublicKey) -> Result<KeyPairKEA, CryptoError> {
    let mut rng = OsRng;

    let half_bits = pk.n.bits() / 2;
    let bound     = BigUint::one() << half_bits;
    let psy       = rng.gen_biguint_below(&bound);

    let enc_one  = p_encrypt(&BigUint::one(), pk)?;
    let enc_psy  = p_encrypt(&psy, pk)?;
    let ct_delta = (enc_one, enc_psy);

    Ok(KeyPairKEA { pk: pk.clone(), ct_delta, psy })
}
