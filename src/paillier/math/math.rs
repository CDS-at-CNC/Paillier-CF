use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use num_integer::Integer;
use rand_core::OsRng;
use rand_core::RngCore;
use crate::crypto_error::crypto_error::CryptoError;

// Taille minimale (bits) de CHAQUE facteur premier p, q.
// PoC/MVP : abaissé à 512 pour une génération de safe primes rapide
// (|n| = 1024 bits). ⚠️ À REMONTER à >= 1536 pour la production.
pub const MIN_KEY_BITS: u64 = 512;

// ---------------------------------------------------------------------------
// Table de petits premiers (crible préliminaire, couvre jusqu'à 2999)
// ---------------------------------------------------------------------------
const SMALL_PRIMES: &[u64] = &[
      3,   5,   7,  11,  13,  17,  19,  23,  29,  31,
     37,  41,  43,  47,  53,  59,  61,  67,  71,  73,
     79,  83,  89,  97, 101, 103, 107, 109, 113, 127,
    131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
    181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
    293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
    359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
    479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
    673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
    743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
    881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
    953, 967, 971, 977, 983, 991, 997,1009,1013,1021,
   1031,1033,1039,1049,1051,1061,1063,1069,1087,1091,
   1093,1097,1103,1109,1117,1123,1129,1151,1153,1163,
   1171,1181,1187,1193,1201,1213,1217,1223,1229,1231,
   1237,1249,1259,1277,1279,1283,1289,1291,1297,1301,
   1303,1307,1319,1321,1327,1361,1367,1373,1381,1399,
   1409,1423,1427,1429,1433,1439,1447,1451,1453,1459,
   1471,1481,1483,1487,1489,1493,1499,1511,1523,1531,
   1543,1549,1553,1559,1567,1571,1579,1583,1597,1601,
   1607,1609,1613,1619,1621,1627,1637,1657,1663,1667,
   1669,1693,1697,1699,1709,1721,1723,1733,1741,1747,
   1753,1759,1777,1783,1787,1789,1801,1811,1823,1831,
   1847,1861,1867,1871,1873,1877,1879,1889,1901,1907,
   1913,1931,1933,1949,1951,1973,1979,1987,1993,1997,
   1999,2003,2011,2017,2027,2029,2039,2053,2063,2069,
   2081,2083,2087,2089,2099,2111,2113,2129,2131,2137,
   2141,2143,2153,2161,2179,2203,2207,2213,2221,2237,
   2239,2243,2251,2267,2269,2273,2281,2287,2293,2297,
   2309,2311,2333,2339,2341,2347,2351,2357,2371,2377,
   2381,2383,2389,2393,2399,2411,2417,2423,2437,2441,
   2447,2459,2467,2473,2477,2503,2521,2531,2539,2543,
   2549,2551,2557,2579,2591,2593,2609,2617,2621,2633,
   2647,2657,2659,2663,2671,2677,2683,2687,2689,2693,
   2699,2707,2711,2713,2719,2729,2731,2741,2749,2753,
   2767,2777,2789,2791,2797,2801,2803,2819,2833,2837,
   2843,2851,2857,2861,2879,2887,2897,2903,2909,2917,
   2927,2939,2953,2957,2963,2969,2971,2999,
];

// Fonction L(u) = (u-1)/n
pub fn l_function(u: &BigUint, n: &BigUint) -> BigUint {
    (u - BigUint::one()) / n
}

// Calcule le pgcd de deux nombres
pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    a.gcd(b)
}

// ---------------------------------------------------------------------------
// Nombre de rounds Miller-Rabin
// ---------------------------------------------------------------------------
fn miller_rabin_rounds(_nbits: u64) -> u32 {
    5
}


// et n = p*q a toujours exactement 2*nbits bits.
// ---------------------------------------------------------------------------
pub fn generate_safe_prime(nbits: u64) -> Result<BigUint, CryptoError> {
    if nbits < MIN_KEY_BITS {
        return Err(CryptoError::KeySizeTooSmall {
            requested: nbits,
            minimum: MIN_KEY_BITS,
        });
    }

    // Besoin d'au moins 4 bits pour avoir des bits nbits-2 et nbits-3 distincts
    if nbits < 4 {
        return Err(CryptoError::KeySizeTooSmall {
            requested: nbits,
            minimum: 4,
        });
    }

    let mut rng = OsRng;
    let rounds = miller_rabin_rounds(nbits);

    loop {
     
        // n = p·q a exactement 2·nbits bits (pas 2·nbits - 1).
        let mut sophie_germain = rng.gen_biguint(nbits - 1);
        sophie_germain.set_bit(nbits - 2, true); // MSB de p' (garantit nbits-1 bits)
        sophie_germain.set_bit(nbits - 3, true); // Second bit haut (garantit plage supérieure)
        sophie_germain.set_bit(0, true);         

       
        if combined_sieve(&sophie_germain) {
            continue;
        }

        // --- Miller-Rabin sur p' ----------

        if !is_probable_prime(&sophie_germain, rounds, &mut rng) {
            continue;
        }

        // --- Construction et test de p = 2p' + 1 -------------------------
        let safe_prime = (&sophie_germain << 1) + BigUint::one();

      
        if is_probable_prime(&safe_prime, rounds, &mut rng) {
            // Vérification de cohérence : s'assurer que safe_prime a bien nbits bits
            debug_assert_eq!(
                safe_prime.bits(),
                nbits,
                "safe_prime devrait avoir {} bits, en a {}",
                nbits,
                safe_prime.bits()
            );
            return Ok(safe_prime);
        }
    }
}


// ---------------------------------------------------------------------------
fn combined_sieve(sophie_germain: &BigUint) -> bool {
    for &sp in SMALL_PRIMES {
        let bp = BigUint::from(sp);

        // Si p' est égal au petit premier lui-même, c'est un vrai premier → ne pas rejeter
        if sophie_germain == &bp {
            return false;
        }

        // Calcule p' mod sp comme u64 (sp < 3000, donc le reste tient en u64)
        let rem_biguint = sophie_germain % &bp;
        // to_u32_digits() retourne les chiffres en base 2^32, little-endian
        let digits = rem_biguint.to_u32_digits();
        let r: u64 = if digits.is_empty() { 0 } else { digits[0] as u64 };

        // p' divisible par sp → rejeter
        if r == 0 {
            return true;
        }

        // 2p'+1 divisible par sp → rejeter
        // (2*r + 1) % sp == 0  (pas de débordement : r < 3000, 2r+1 < 6001, tient en u64)
        if (2 * r + 1) % sp == 0 {
            return true;
        }
    }
    false
}

// Vérifie si n est divisible par un des petits premiers de la table.
// Conservé pour usage éventuel hors du chemin safe prime.
#[allow(dead_code)]
fn is_divisible_by_small_prime(n: &BigUint) -> bool {
    for &p in SMALL_PRIMES {
        let bp = BigUint::from(p);
        if n == &bp {
            return false;
        }
        if (n % &bp).is_zero() {
            return true;
        }
    }
    false
}

fn is_probable_prime(n: &BigUint, rounds: u32, rng: &mut impl RngCore) -> bool {
    if n <= &BigUint::one() { return false; }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) { return true; }
    if n.is_even() { return false; }
    for &p in SMALL_PRIMES {
        if n == &BigUint::from(p) { return true; }
    }
    if n < &BigUint::from(5u32) { return false; }

    let n_minus_1 = n - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    'witness: for _ in 0..rounds {
        let a = rng.gen_biguint_range(
            &BigUint::from(2u32),
            &(n - BigUint::from(2u32)),
        );
        let mut x = a.modpow(&d, n);
        if x == BigUint::one() || x == n_minus_1 {
            continue 'witness;
        }
        for _ in 0..r.saturating_sub(1) {
            x = (&x * &x) % n;
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Calcule l'inverse modulaire de a mod n.
// Retourne Err(CryptoError::NoModularInverse) si gcd(a,n) != 1.
// ---------------------------------------------------------------------------
pub fn mod_inverse(a: &BigUint, n: &BigUint) -> Result<BigUint, CryptoError> {
    let (g, x, _) = extended_gcd(a, n);
    if g != BigUint::one() {
        return Err(CryptoError::NoModularInverse);
    }

    use num_bigint::BigInt;
    let n_big = BigInt::from(n.clone());
    let mut x_mod = x % &n_big;
    if x_mod < BigInt::zero() {
        x_mod += &n_big;
    }

    x_mod.to_biguint().ok_or(CryptoError::NegativeConversion)
}

fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, num_bigint::BigInt, num_bigint::BigInt) {
    use num_bigint::BigInt;

    let (mut old_r, mut r) = (BigInt::from(a.clone()), BigInt::from(b.clone()));
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());

    while r != BigInt::zero() {
        let quotient = &old_r / &r;

        let temp_r = r.clone();
        r = old_r - &quotient * &r;
        old_r = temp_r;

        let temp_s = s.clone();
        s = old_s - &quotient * &s;
        old_s = temp_s;

        let temp_t = t.clone();
        t = old_t - &quotient * &t;
        old_t = temp_t;
    }

    let gcd_val = old_r.to_biguint().unwrap_or_default();

    (gcd_val, old_s, old_t)
}

pub fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) / gcd(a, b)
}