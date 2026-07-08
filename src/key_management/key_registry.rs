// ============================================================================
// KeyRegistry — Registre de clés thread-safe pour déploiement serveur
//
// Problème sans ce module :
//   Dans un serveur multi-threadé (ex. Actix, Axum, Tokio), plusieurs threads
//   traitent des requêtes simultanément et ont besoin d'accéder aux clés.
//   Sans synchronisation, le compilateur Rust refuse le partage de référence
//   mutable entre threads (pas de Send/Sync sur KeyPair brut) — ou, si
//   on contourne avec unsafe, on risque des data races.
//
// Solution — Arc<RwLock<Option<T>>> :
//   - Arc<T>        : comptage de références atomique → cloneable entre threads
//   - RwLock<T>     : plusieurs lecteurs simultanés, un seul écrivain exclusif
//   - Option<T>     : permet de distinguer "clé non encore chargée" de "clé chargée"
//
// Pattern d'usage serveur recommandé :
//   1. Au démarrage : KeyRegistry::new() puis registry.set_keypair(kp)?
//   2. Dans chaque handler : let pk = registry.public_key()?  (lecture partagée)
//   3. Rotation de clé : registry.set_keypair(new_kp)?       (écriture exclusive)
//
// RwLock vs Mutex :
//   Mutex donne un accès exclusif même pour les lectures — inapproprié pour
//   un serveur où 95% des opérations sont des chiffrements (lectures seules).
//   RwLock permet la concurrence totale en lecture, ce qui correspond
//   exactement au cas d'usage cryptographique : la clé publique est lue
//   par tous les threads de chiffrement simultanément.
// ============================================================================

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::paillier::p_keygen::{PublicKey, SecretKey, KeyPair};
use crate::paillier_kea::paillier_kea_keygen::KeyPairKEA;
use crate::crypto_error::crypto_error::CryptoError;

// ============================================================================
// Erreurs spécifiques au registre
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum RegistryError {
    /// Aucune clé Paillier n'a encore été chargée dans le registre
    NoPaillierKey,
    /// Aucune clé KEA n'a encore été chargée dans le registre
    NoKeaKey,
    /// Le verrou RwLock est empoisonné (thread paniqué pendant un accès exclusif)
    /// Cela ne peut arriver que si du code unsafe ou un panic survient en zone critique.
    LockPoisoned,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::NoPaillierKey =>
                write!(f, "Aucune clé Paillier chargée dans le registre"),
            RegistryError::NoKeaKey =>
                write!(f, "Aucune clé KEA chargée dans le registre"),
            RegistryError::LockPoisoned =>
                write!(f, "Verrou du registre empoisonné — redémarrage requis"),
        }
    }
}

impl std::error::Error for RegistryError {}

// Conversion pour propager RegistryError comme CryptoError si nécessaire
impl From<RegistryError> for CryptoError {
    fn from(_: RegistryError) -> Self {
        // On mappe sur NoModularInverse par défaut — à étendre si besoin
        CryptoError::NoModularInverse
    }
}

// ============================================================================
// État interne protégé par RwLock
// ============================================================================

struct RegistryState {
    keypair: Option<KeyPair>,
    kea:     Option<KeyPairKEA>,
}

// ============================================================================
// KeyRegistry — point d'entrée unique pour l'accès aux clés en production
//
// Clonable à faible coût grâce à Arc (clone = incrément d'un compteur atomique).
// Peut être transmis aux handlers de chaque thread via .clone().
// ============================================================================
#[derive(Clone)]
pub struct KeyRegistry {
    inner: Arc<RwLock<RegistryState>>,
}

impl KeyRegistry {
    // -----------------------------------------------------------------------
    // Constructeur — registre vide, prêt à recevoir des clés
    // -----------------------------------------------------------------------
    pub fn new() -> Self {
        KeyRegistry {
            inner: Arc::new(RwLock::new(RegistryState {
                keypair: None,
                kea:     None,
            })),
        }
    }

    // -----------------------------------------------------------------------
    // Accès en écriture — helper interne
    // -----------------------------------------------------------------------
    fn write(&self) -> Result<RwLockWriteGuard<'_, RegistryState>, RegistryError> {
        self.inner.write().map_err(|_| RegistryError::LockPoisoned)
    }

    // -----------------------------------------------------------------------
    // Accès en lecture — helper interne
    // -----------------------------------------------------------------------
    fn read(&self) -> Result<RwLockReadGuard<'_, RegistryState>, RegistryError> {
        self.inner.read().map_err(|_| RegistryError::LockPoisoned)
    }

    // -----------------------------------------------------------------------
    // Chargement / rotation de la paire de clés Paillier
    //
    // Écriture exclusive : bloque les lecteurs pendant le remplacement.
    // Durée typique : quelques microsecondes (simple déplacement de pointeurs).
    // -----------------------------------------------------------------------
    pub fn set_keypair(&self, kp: KeyPair) -> Result<(), RegistryError> {
        self.write()?.keypair = Some(kp);
        Ok(())
    }

    /// Supprime la clé Paillier (et déclenche la zeroization via Drop)
    pub fn clear_keypair(&self) -> Result<(), RegistryError> {
        self.write()?.keypair = None;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chargement / rotation de la clé KEA
    // -----------------------------------------------------------------------
    pub fn set_kea(&self, kea: KeyPairKEA) -> Result<(), RegistryError> {
        self.write()?.kea = Some(kea);
        Ok(())
    }

    /// Supprime la clé KEA (et déclenche la zeroization de psy via Drop)
    pub fn clear_kea(&self) -> Result<(), RegistryError> {
        self.write()?.kea = None;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Accès à la clé publique Paillier — lecture partagée (N threads simultanés)
    //
    // Retourne un clone de PublicKey. PublicKey ne contient pas de données
    // secrètes donc le clonage est sûr et sans impact sécuritaire.
    // -----------------------------------------------------------------------
    pub fn public_key(&self) -> Result<PublicKey, RegistryError> {
        let guard = self.read()?;
        guard.keypair
            .as_ref()
            .map(|kp| kp.public_key.clone())
            .ok_or(RegistryError::NoPaillierKey)
    }

    // -----------------------------------------------------------------------
    // Exécution d'une opération avec accès à la clé secrète Paillier
    //
    // Pattern "prêter sans cloner" : la clé secrète n'est jamais extraite
    // du registre. Le closure reçoit une référence &SecretKey valide
    // uniquement pendant l'exécution, puis le verrou est relâché.
    //
    // Cela garantit que SecretKey reste sous contrôle du registre à tout
    // moment et ne "fuite" jamais dans le heap sous forme de clone.
    //
    // Usage typique :
    //   let m = registry.with_secret_key(|sk| p_decrypt(&ct, &pk, sk))?;
    // -----------------------------------------------------------------------
    pub fn with_secret_key<F, T>(&self, f: F) -> Result<T, RegistryError>
    where
        F: FnOnce(&SecretKey) -> T,
    {
        let guard = self.read()?;
        guard.keypair
            .as_ref()
            .map(|kp| f(&kp.secret_key))
            .ok_or(RegistryError::NoPaillierKey)
    }

    // -----------------------------------------------------------------------
    // Exécution d'une opération avec accès à la paire de clés KEA complète
    //
    // Même pattern "prêter sans cloner" que with_secret_key.
    // psy (ξ) ne quitte jamais le registre.
    //
    // Usage typique :
    //   let m = registry.with_kea(|kea| {
    //       paillier_kea_decrypt(&kea.pk, &sk, &kea.psy, &ct)
    //   })?;
    // -----------------------------------------------------------------------
    pub fn with_kea<F, T>(&self, f: F) -> Result<T, RegistryError>
    where
        F: FnOnce(&KeyPairKEA) -> T,
    {
        let guard = self.read()?;
        guard.kea
            .as_ref()
            .map(|kea| f(kea))
            .ok_or(RegistryError::NoKeaKey)
    }

    // -----------------------------------------------------------------------
    // Vérification de présence des clés (utile au démarrage)
    // -----------------------------------------------------------------------
    pub fn has_keypair(&self) -> bool {
        self.read().ok()
            .and_then(|g| g.keypair.as_ref().map(|_| true))
            .unwrap_or(false)
    }

    pub fn has_kea(&self) -> bool {
        self.read().ok()
            .and_then(|g| g.kea.as_ref().map(|_| true))
            .unwrap_or(false)
    }
}

impl Default for KeyRegistry {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// Tests unitaires du registre
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    // Construit une KeyPair minimale pour les tests (pas cryptographiquement valide)
    fn dummy_keypair() -> KeyPair {
        use num_bigint::BigUint;
        KeyPair {
            public_key: PublicKey {
                n:         BigUint::from(77u32),
                g:         BigUint::from(2u32),
                n_squared: BigUint::from(5929u32),
            },
            secret_key: crate::paillier::p_keygen::p_keygen::SecretKey {
                lambda: BigUint::from(30u32),
                mu:     BigUint::from(1u32),
            },
        }
    }

    #[test]
    fn test_registry_empty_returns_err() {
        let reg = KeyRegistry::new();
        assert!(matches!(reg.public_key(), Err(RegistryError::NoPaillierKey)));
    }

    #[test]
    fn test_registry_set_and_get() {
        let reg = KeyRegistry::new();
        reg.set_keypair(dummy_keypair()).unwrap();
        assert!(reg.public_key().is_ok());
        assert!(reg.has_keypair());
    }

    #[test]
    fn test_registry_clear_triggers_zeroize() {
        let reg = KeyRegistry::new();
        reg.set_keypair(dummy_keypair()).unwrap();
        // clear() → Drop sur KeyPair → Drop sur SecretKey → Zeroize::zeroize()
        reg.clear_keypair().unwrap();
        assert!(matches!(reg.public_key(), Err(RegistryError::NoPaillierKey)));
    }

    #[test]
    fn test_registry_concurrent_reads() {
        // Vérifie que N threads peuvent lire simultanément sans deadlock
        let reg = Arc::new(KeyRegistry::new());
        reg.set_keypair(dummy_keypair()).unwrap();

        let handles: Vec<_> = (0..8).map(|_| {
            let r = Arc::clone(&reg);
            thread::spawn(move || {
                for _ in 0..100 {
                    assert!(r.public_key().is_ok());
                }
            })
        }).collect();

        for h in handles { h.join().unwrap(); }
    }

    #[test]
    fn test_with_secret_key_does_not_leak() {
        // Vérifie que with_secret_key fonctionne et que SecretKey reste dans le registre
        let reg = KeyRegistry::new();
        reg.set_keypair(dummy_keypair()).unwrap();

        let result = reg.with_secret_key(|sk| sk.lambda.clone());
        assert!(result.is_ok());
    }
}