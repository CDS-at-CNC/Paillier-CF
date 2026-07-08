use num_bigint::BigUint;
use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::crypto_error::CryptoError;
use crate::karatsuba_mul::karatsuba_mul::fast_mul;

// ---------------------------------------------------------------------------
// cf_mul — Multiplication homomorphique Catalano-Fiore
//
// Entrées : deux CF-chiffrés CF(m, r) = (c0, c1) et CF(m', r') = (c0', c1')
//   où  c0  = m  - r  mod n,   c1  = Enc(r)
//       c0' = m' - r' mod n,   c1' = Enc(r')
//
// Sortie  : un triplet (C0, C1, C2) tel que cf_mul_dec reconstruit m*m'.
//
// Algèbre Catalano-Fiore (version 2-linéaire) :
//   m * m' = (c0 + r)(c0' + r')
//           = c0*c0' + c0*r' + r*c0' + r*r'
//
//   On chiffre la partie déterministe (c0*c0') avec du bruit frais :
//     enc_prod = Enc(c0 * c0' mod n)
//
//   On masque avec les termes croisés (homomorphisme Paillier) :
//     C0 = enc_prod * c1'^{c0} * c1^{c0'}  mod n²
//        = Enc(c0*c0' + r'*c0 + r*c0')
//
//   Le terme r*r' est récupéré lors du déchiffrement via C1 et C2 :
//     C1 = c1  = Enc(r)
//     C2 = c1' = Enc(r')
//
//   Déchiffrement (cf_mul_dec) :
//     Dec(C0) + Dec(C1)*Dec(C2) = (c0*c0' + r'*c0 + r*c0') + r*r'
//                                = m*m'  mod n  ✓
//
// CORRECTIONS :
//   1. COPIER-COLLER corrigé : la ligne
//        let c0_snd = mul(product_enc_c1c0_p, c1_pc0)   ← c1_pc0 utilisé 2×
//      était fausse. La construction correcte est :
//        step1 = enc_prod  * c1'^{c0}   (terme c1_p ^ c0)
//        C0    = step1     * c1^{c0'}   (terme c1   ^ c0_p)  ← c1c0_p
//
//   2. Modulus corrigé pour les multiplications de CHIFFRÉS :
//      multiple_precision_mul utilise maintenant le modulus explicite.
//      - enc_prod, c1c0_p, c1_pc0 vivent dans Z_{n²} → modulus = n_squared
//      - product_c0 est un plaintext dans Z_n          → modulus = n
// ---------------------------------------------------------------------------
pub fn cf_mul(
	ciphert:  &(BigUint, BigUint),
	ciphert1: &(BigUint, BigUint),
	pk:       &PublicKey,
) -> Result<(BigUint, BigUint, BigUint), CryptoError> {

	let c0   = &ciphert.0;    // m  - r  mod n
	let c1   = &ciphert.1;    // Enc(r)  dans Z_{n²}

	let c0_p = &ciphert1.0;   // m' - r' mod n
	let c1_p = &ciphert1.1;   // Enc(r') dans Z_{n²}

	// ── Étape 1 : chiffrer le produit des composantes plaintexts ────────────
	// product_c0 = c0 * c0' mod n   (plaintext → modulus = n)
	let product_c0 = fast_mul(c0, c0_p, &pk.n)?;

	// enc_prod = Enc(c0 * c0') dans Z_{n²}
	let enc_prod = p_encrypt(&product_c0, pk)?;

	// ── Étape 2 : termes croisés (exponentiations dans Z_{n²}) ──────────────
	// c1^{c0'}  = Enc(r)^{c0'} = Enc(r * c0')   mod n²
	// CORRECTION : c'était `c1.modpow(c0_p, ...)` — nom de variable c1c0_p
	let c1c0_p = c1.modpow(c0_p, &pk.n_squared);   // Enc(r * c0')

	// c1'^{c0} = Enc(r')^{c0} = Enc(r' * c0)   mod n²
	let c1_pc0 = c1_p.modpow(c0, &pk.n_squared);   // Enc(r' * c0)

	// ── Étape 3 : assemblage de C0 ──────────────────────────────────────────
	// C0 = enc_prod * c1'^{c0} * c1^{c0'}   mod n²
	//    = Enc(c0*c0') * Enc(r'*c0) * Enc(r*c0')
	//    = Enc(c0*c0' + r'*c0 + r*c0')   mod n²
	//
	// CORRECTION : les deux multiplications utilisent maintenant n_squared
	// et c1c0_p (et non c1_pc0 deux fois comme avant).
	let step1 = fast_mul(&enc_prod, &c1_pc0, &pk.n_squared)?;  // enc_prod * c1'^{c0}
	let c0_res = fast_mul(&step1,   &c1c0_p, &pk.n_squared)?;  // step1    * c1^{c0'}
	//            CORRECTION ↑ : c1c0_p ici (avant : c1_pc0 deux fois → FAUX)

	// ── Étape 4 : conserver C1 et C2 pour le déchiffrement ──────────────────
	// C1 = c1  = Enc(r),   C2 = c1' = Enc(r')
	// cf_mul_dec calculera r*r' = Dec(C1)*Dec(C2) et l'ajoutera à Dec(C0).
	let c1_res = c1.clone();
	let c2_res = c1_p.clone();

	Ok((c0_res, c1_res, c2_res))
}

