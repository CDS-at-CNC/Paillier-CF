use num_bigint::BigUint;
use crate::paillier::math::l_function;
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::crypto_error::CryptoError;



pub fn p_decrypt(c: &BigUint, pk: &PublicKey, sk: &SecretKey) -> Result<BigUint, CryptoError> {
    

	if c >= &pk.n_squared {
		return Err(CryptoError::CiphertextOutOfRange);
}

    
    // Calcule c^lambda mod n^2

    let c_lambda = c.modpow(&sk.lambda, &pk.n_squared);
    
    // Calcule L(c^lambda mod n^2)
	
    let l_c_lambda = l_function(&c_lambda, &pk.n);
    
    // Calcule m = L(c^lambda mod n^2) * mu (mod n)

    let m = (&l_c_lambda * &sk.mu) % &pk.n;
    
    Ok(m)


}


