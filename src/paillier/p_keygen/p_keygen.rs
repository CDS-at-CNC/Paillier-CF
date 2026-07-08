use num_bigint::BigUint;
use num_traits::One;
use zeroize::Zeroize;
use crate::paillier::math::{l_function, gcd, lcm, mod_inverse, generate_safe_prime};
use crate::crypto_error::crypto_error::CryptoError;

// ============================================================================
// Clé publique Paillier — pas de données secrètes, pas de zeroize nécessaire
// ============================================================================
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub n:         BigUint,
    pub g:         BigUint,
    pub n_squared: BigUint,
}

// ============================================================================
// Helper : efface les octets internes d'un BigUint
// ============================================================================
fn zeroize_biguint(n: &mut BigUint) {
    let bits = n.bits() as usize;
    if bits > 0 {
        *n = BigUint::from_bytes_be(&vec![0u8; (bits + 7) / 8]);
    }
    *n = BigUint::default();
}

// ============================================================================
// Clé secrète Paillier — ZEROISÉE À LA DESTRUCTION
// ============================================================================
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub lambda: BigUint,
    pub mu:     BigUint,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        zeroize_biguint(&mut self.lambda);
        zeroize_biguint(&mut self.mu);
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// Paire de clés
// ============================================================================
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

// ============================================================================
// Génération de clés Paillier
// ============================================================================
pub fn p_keygen(nbits: u64) -> Result<KeyPair, CryptoError> {
    // Deux safe primes distincts p et q tels que p = 2p'+1, q = 2q'+1
    let p = generate_safe_prime(nbits)?;
    let mut q = generate_safe_prime(nbits)?;
    while p == q {
        q = generate_safe_prime(nbits)?;
    }

    let n         = &p * &q;
    let n_squared = &n * &n;

    let p_minus_1 = &p - BigUint::one();
    let q_minus_1 = &q - BigUint::one();
    let phi_n     = &p_minus_1 * &q_minus_1;

    
    if gcd(&n, &phi_n) != BigUint::one() {
        return Err(CryptoError::NoModularInverse);
    }

    let lambda = lcm(&p_minus_1, &q_minus_1);

    let g = &n + BigUint::one();


    let g_lambda = (BigUint::one() + &lambda * &n) % &n_squared;

    let l_g_lambda = l_function(&g_lambda, &n);

   
    if gcd(&l_g_lambda, &n) != BigUint::one() {
        return Err(CryptoError::NoModularInverse);
    }

    let mu = mod_inverse(&l_g_lambda, &n)?;

    Ok(KeyPair {
        public_key: PublicKey { n, g, n_squared },
        secret_key: SecretKey { lambda, mu },
    })
}