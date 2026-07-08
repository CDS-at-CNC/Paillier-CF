use num_bigint::BigUint;
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
use crate::paillier_kea::paillier_kea_img_verif::paillier_kea_img_verif;
use crate::crypto_error::crypto_error::CryptoError;

pub fn paillier_kea_decrypt(
	pk: &PublicKey, 
	sk: &SecretKey, 
	psy: &BigUint,
	ct: &(BigUint, BigUint),
) -> Result<BigUint, CryptoError> {


	let valid = paillier_kea_img_verif(pk, sk, psy, ct)?;

	if !valid {

		return Err(CryptoError::KeaImVerFailed);

}




	let message = p_decrypt(&ct.0, pk, sk)?;


	Ok(message)

} 