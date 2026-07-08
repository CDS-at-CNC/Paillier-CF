use num_bigint::BigUint;
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::crypto_error::CryptoError;



pub fn paillier_kea_img_verif(
	pk: &PublicKey, 
	sk: &SecretKey,
	psy: &BigUint,
	ct: &(BigUint, BigUint),
) -> Result<bool, CryptoError> {


	let mu_0 = p_decrypt(&ct.0, pk, sk)?;
 
	let mu_1 = p_decrypt(&ct.1, pk, sk)?;

	let attendu = (psy * &mu_0) % &pk.n;

	Ok(attendu == mu_1)

}