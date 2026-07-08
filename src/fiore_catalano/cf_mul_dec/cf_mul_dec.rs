use num_bigint::BigUint;
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::crypto_error::CryptoError;



pub fn cf_mul_dec(
	ciphert: &(BigUint, BigUint, BigUint), 
	pk: &PublicKey, 
	sk: &SecretKey,
) -> Result<BigUint, CryptoError> {


	let c0 = &ciphert.0;

	let _c1 = &ciphert.1;

	let _c2 = &ciphert.2;

	// Déchiffre uniquement la première composante : c0 contient
	// déjà la valeur souhaitée (m1*m2 - r1*r2) après construction
	// dans `cf_mul` (voir algèbre de Catalano–Fiore). Les autres
	// composantes sont conservées pour d'autres usages.
	let dec_c0 = p_decrypt(c0, pk, sk)?;

	let dec_c1 = p_decrypt(_c1, pk, sk)?;

	let dec_c2 = p_decrypt(_c2, pk, sk)?;

	let result = (dec_c0 + (dec_c1 * dec_c2)) % &pk.n;

	Ok(result)


}  
