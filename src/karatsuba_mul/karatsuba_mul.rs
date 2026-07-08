use num_bigint::BigUint;
use num_traits::Zero;
use crate::crypto_error::crypto_error::CryptoError;
// PublicKey n'est plus nécessaire ici — le modulus est passé explicitement
pub use crate::paillier::math::{l_function, gcd, generate_safe_prime, mod_inverse, lcm};

// ---------------------------------------------------------------------------
// multiple_precision_mul
//
// CORRECTION : le modulus est désormais passé explicitement en paramètre
// (plus de `pk: &PublicKey` dont on n'utilisait que `pk.n`).
//
// Les appelants qui multiplient des CHIFFRÉS Paillier passent `&pk.n_squared`.
// Les appelants qui multiplient des PLAINTEXTS passent `&pk.n`.
// ---------------------------------------------------------------------------
pub fn fast_mul(
    a:       &BigUint,
    b:       &BigUint,
    modulus: &BigUint,
) -> Result<BigUint, CryptoError> {
    if modulus.is_zero() {
        return Err(CryptoError::InvalidInput(
            "multiple_precision_mul : modulus ne peut pas être zéro".into(),
        ));
    }
    Ok(karatsuba_mul(a, b, modulus))
}

// ---------------------------------------------------------------------------
// karatsuba_mul
//
// CORRECTIONS apportées :
//
//   1. Suppression de montgomery_reduce entre les sous-produits.
//      L'identité  a·b = z2·B² + z1·B + z0  n'est valide QUE si z0, z1, z2
//      sont calculés en entier. Toute réduction intermédiaire tronque les
//      bits de poids fort et brise l'identité mathématique.
//
//   2. Suppression de la pseudo-réduction de Montgomery (mod_inverse) qui :
//        - pouvait échouer silencieusement → unwrap_or_default() retournait 0
//        - était recalculée à chaque appel (coût O(log²n) inutile)
//        - n'était pas une vraie réduction de Montgomery (R non précalculé)
//
//   3. Seuil relevé à 512 bits : en dessous, la multiplication directe est
//      plus rapide que le découpage récursif.
//
//   4. Masque bas avec `& (base - 1)` au lieu de `% base` (base = 2^k,
//      donc le masque est exact et plus lisible).
//
//   5. Décalages lors de la reconstruction réduits mod n au fur et à mesure
//      pour éviter une explosion mémoire sur des BigUint de milliers de bits.
// ---------------------------------------------------------------------------
pub fn karatsuba_mul(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let a_bits = a.bits();
    let b_bits = b.bits();

    // Cas de base : multiplication directe pour les petits opérandes
    if a_bits < 512 || b_bits < 512 {
        return (a * b) % n;
    }

    // k = moitié de la longueur du plus grand opérande (en bits)
    let k = std::cmp::max(a_bits, b_bits) / 2;

    // base = 2^k, mask = 2^k - 1
    let base = BigUint::from(1u32) << k;
    let mask = &base - BigUint::from(1u32);

    // Décomposition : x = x_high * 2^k + x_low
    let a_low  = a & &mask;
    let a_high = a >> k;
    let b_low  = b & &mask;
    let b_high = b >> k;

    // Trois produits récursifs — SANS réduction intermédiaire
    let z0      = karatsuba_mul(&a_low,               &b_low,               n);
    let z2      = karatsuba_mul(&a_high,              &b_high,              n);
    let z1_full = karatsuba_mul(&(&a_low + &a_high),  &(&b_low + &b_high),  n);

    // z1 = z1_full - z0 - z2   (mod n)
    // On ajoute 2n avant les soustractions pour rester positif.
    let z1 = (z1_full + n + n - &z0 - &z2) % n;

    // Reconstruction : (z2 << 2k) + (z1 << k) + z0   (mod n)
    // Les décalages sont réduits mod n immédiatement pour éviter
    // une explosion de la taille mémoire.
    let part2 = (&z2 << (2 * k)) % n;
    let part1 = (&z1 << k) % n;

    (part2 + part1 + z0) % n
}

