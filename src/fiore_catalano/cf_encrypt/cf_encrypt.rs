use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use num_bigint::BigUint;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::crypto_error::CryptoError; 


pub fn cf_encrypt(
    message: &BigUint,
    masque: &BigUint,
    pk: &PublicKey
) -> Result<(BigUint, BigUint), CryptoError> {

    if message >= &pk.n {
	return Err(CryptoError::MessageOutOfRange);
} 


    let m = message % &pk.n;

    let r = masque % &pk.n;

    let c0 = if m >= r {

        &m - &r

    } else {

        &m + &pk.n - &r
    };

    let c0 = c0 % &pk.n;

    let c1 = p_encrypt(&r, pk)?; // pas besoin de re-modulo n^2

    Ok((c0, c1))
}
