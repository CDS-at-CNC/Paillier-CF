// Déclaration des modules
pub mod crypto_error;
pub mod paillier;
pub mod exactmatch;       // ← décommenté : module PSI ExactMatch
pub mod net_protocol;     // ← ajouté    : sérialisation + BandwidthMeter tunnel socket
pub mod fiore_catalano;
pub mod key_management;
pub mod paillier_kea;
pub mod karatsuba_mul;
pub mod hepseudo;         // ← FHEnymisation (ported from v0.4.0 HEpseudo)

// Bindings Python (PyO3) — compilés UNIQUEMENT avec `--features python`
// (utilisé par maturin). N'affecte jamais les binaires server/client/
// paillier_crypto, qui restent compilés sans dépendance à pyo3.
#[cfg(feature = "python")]
pub mod pybindings;

pub use crate::paillier::math;
pub use crate::paillier::p_keygen;
pub use crate::paillier::p_encrypt;
pub use crate::paillier::p_decrypt;

// Fonctions mathématiques principales
pub use crate::paillier::math::{l_function, gcd, generate_safe_prime, mod_inverse, lcm};

// Types depuis keygen
pub use p_keygen::p_keygen::{SecretKey, KeyPair};

// Erreur centralisée
pub use crypto_error::crypto_error::CryptoError;

// Registre de clés thread-safe — point d'entrée pour les serveurs multi-threadés
pub use key_management::{KeyRegistry, RegistryError};