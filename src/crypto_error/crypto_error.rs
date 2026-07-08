// ===========================================================================
// Gestion centralisée des erreurs cryptographiques
//
// Tous les modules utilisent ce type au lieu de panic!/assert!/unwrap().
// L'appelant (serveur web, API) reçoit une Err(...) et peut répondre
// proprement au client sans crasher le thread.
// ===========================================================================

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum CryptoError {
    // --- Erreurs de paramètres d'entrée ---
    /// Le message m est >= n (hors domaine plaintext Paillier)
    MessageOutOfRange,
    /// Le chiffré c est >= n² (hors domaine ciphertext Paillier)
    CiphertextOutOfRange,
    /// La taille de clé demandée est trop petite (< MIN_KEY_BITS)
    KeySizeTooSmall { requested: u64, minimum: u64 },

    // --- Erreurs mathématiques internes ---
    /// L'inverse modulaire n'existe pas (gcd != 1)
    NoModularInverse,
    /// Conversion BigInt -> BigUint échouée (résultat négatif — invariant interne)
    NegativeConversion,

    // --- Erreurs de stockage / parsing des clés ---
    /// Parsing hexadécimal invalide dans un champ de clé JSON
    HexParseError,
    /// Champ hex trop long : vecteur DoS potentiel (conversion BigUint coûteuse)
    HexFieldTooLong { actual: usize, maximum: usize },
    /// n_squared != n*n au chargement : fichier corrompu ou falsifié
    KeyCoherenceError,

    // --- Erreurs KEA ---
    /// La vérification d'image KEA a échoué (chiffré invalide ou falsifié)
    KeaImVerFailed,

    InvalidInput(String), // Erreur générique pour les entrées invalides (ex: base zéro dans la fonction de représentation en base)


}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::MessageOutOfRange =>
                write!(f, "Le message doit être dans [0, n)"),
            CryptoError::CiphertextOutOfRange =>
                write!(f, "Le chiffré doit être dans [0, n²)"),
            CryptoError::KeySizeTooSmall { requested, minimum } =>
                write!(f, "Taille de clé {requested} bits insuffisante, minimum requis : {minimum} bits"),
            CryptoError::NoModularInverse =>
                write!(f, "Impossible de calculer l'inverse modulaire (gcd != 1)"),
            CryptoError::NegativeConversion =>
                write!(f, "Conversion interne BigInt -> BigUint : résultat négatif inattendu"),
            CryptoError::HexParseError =>
                write!(f, "Parsing hexadécimal invalide dans le fichier de clés"),
            CryptoError::HexFieldTooLong { actual, maximum } =>
                write!(f, "Champ hexadécimal trop long : {actual} caractères (maximum autorisé : {maximum})"),
            CryptoError::KeyCoherenceError =>
                write!(f, "Fichier de clés incohérent : n_squared != n*n (corrompu ou falsifié)"),
            CryptoError::KeaImVerFailed =>
                write!(f, "Vérification d'image KEA échouée : chiffré invalide ou falsifié"),
            
            CryptoError::InvalidInput(msg) =>
                write!(f, "Entrée invalide : {msg}"),
        }
    }
}

impl std::error::Error for CryptoError {}