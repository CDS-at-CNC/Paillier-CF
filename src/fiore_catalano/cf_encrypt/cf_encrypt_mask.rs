use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use num_bigint::BigUint;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::crypto_error::CryptoError;


// ---------------------------------------------------------------------------
// masque_encrypt — Chiffre un masque r avec Paillier
//
// CORRECTIONS :
//   1. Type de retour changé de `Result<BigUint, &'static str>` en
//      `Result<BigUint, CryptoError>` — cohérent avec p_encrypt et le reste
//      du projet. &'static str ne permet pas de transmettre l'erreur réelle.
//
//   2. Suppression du `Ok(mask_encrypt_b)` incorrect :
//      `p_encrypt` retourne `Result<BigUint, CryptoError>`, pas un `BigUint`.
//      Le code original faisait `Ok(Result<...>)`, ce qui crée un type
//      `Result<Result<BigUint, CryptoError>, &'static str>` au lieu de
//      `Result<BigUint, &'static str>` — erreur de type / bug logique.
//
//   3. On utilise l'opérateur `?` pour propager l'erreur directement.
// ---------------------------------------------------------------------------
pub fn masque_encrypt(masque: &BigUint, pk: &PublicKey) -> Result<BigUint, CryptoError> {
	// p_encrypt retourne Result<BigUint, CryptoError>
	// `?` dépaquète le Ok(BigUint) ou propage le Err(CryptoError)
	p_encrypt(masque, pk)
}

