
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
use num_bigint::BigUint;
use crate::crypto_error::crypto_error::CryptoError;


// ---------------------------------------------------------------------------
// cf_add_dec — Déchiffrement d'un CF-chiffré (issu d'un cf_add ou direct)
//
// Encodage CF : CF(m, r) = (c0, c1) avec c0 = m - r mod n, c1 = Enc(r)
//
// Déchiffrement :  m = c0 + Dec(c1)  mod n
//                    = (m - r) + r   mod n  = m  ✓
//
// CORRECTIONS :
//   1. c0 est une valeur EN CLAIR dans Z_n — on ne la déchiffre PAS.
//      Avant, le code commentait `p_decrypt(&c0, ...)` et utilisait c0
//      directement, ce qui était correct par hasard mais mal documenté.
//
//   2. `c0 + dec_masque` est bien la reconstruction attendue.
//      La formule est désormais clairement justifiée par l'algèbre CF.
//
//   3. Après cf_add :
//        c0_res = (m-r) + (m'-r') mod n
//        c1_res = Enc(r + r')
//      donc Dec(c1_res) = r + r', et
//        c0_res + Dec(c1_res) = (m+m') - (r+r') + (r+r') = m+m' mod n  ✓
// ---------------------------------------------------------------------------
pub fn cf_add_dec(
	ciphert: &(BigUint, BigUint), 
	pk : &PublicKey, 
	sk : &SecretKey,
) -> Result<BigUint, CryptoError> {

	// c0 : partie plaintext masquée  →  valeur en clair, PAS de déchiffrement
	let c0 = &ciphert.0;

	// c1 : Enc(r) ou Enc(r + r') après addition  →  on déchiffre pour récupérer r
	let c1 = &ciphert.1;

	// Dec(c1) = r  (ou r+r' après addition)
	let dec_masque = p_decrypt(c1, pk, sk)?;

	// Reconstruction : m = c0 + r = (m - r) + r  mod n
	let message = (c0 + dec_masque) % &pk.n;

	Ok(message)

}
