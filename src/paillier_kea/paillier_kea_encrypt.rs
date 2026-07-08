use num_bigint::{BigUint, RandBigInt};
use rand_core::OsRng;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::crypto_error::CryptoError;




pub fn paillier_kea_encrypt(
	message: &BigUint, 
	pk: &PublicKey,
	ct_delta: &(BigUint, BigUint),
) -> Result<(BigUint, BigUint), CryptoError> {


	let mut rng = OsRng;

	let r0 = rng.gen_biguint_below(&pk.n);

	let r1 = rng.gen_biguint_below(&pk.n);

	let r0_n = r0.modpow(&pk.n, &pk.n_squared);

	let r1_n = r1.modpow(&pk.n, &pk.n_squared);

	let first_component_kea = ct_delta.0.modpow(message, &pk.n_squared);

	let second_component_kea = ct_delta.1.modpow(message, &pk.n_squared); 

	let c0 = (first_component_kea * r0_n) % &pk.n_squared;

	let c1 = (second_component_kea * r1_n) % &pk.n_squared;

	Ok((c0, c1))

} 