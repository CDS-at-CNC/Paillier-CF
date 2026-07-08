use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use std::io;
use num_bigint::BigUint;
use num_traits::Num;
use crate::paillier::p_keygen::{PublicKey, SecretKey, KeyPair};
use crate::crypto_error::crypto_error::CryptoError;

// ============================================================================
// Protection DoS parsing — limites de taille des entrées
//
// Sans ces limites, un attaquant qui contrôle un fichier de clés JSON peut :
//   - Soumettre un fichier de plusieurs Go → lecture en mémoire non bornée,
//     le serveur est tué par l'OOM killer (déni de service).
//   - Soumettre un champ hex de plusieurs Mo → BigUint::from_str_radix est
//     O(n²) en taille d'entrée, le CPU est saturé pendant plusieurs secondes
//     par requête (déni de service CPU).
//
// Ces constantes sont vérifiées AVANT toute opération coûteuse.
// Dimensionnées pour des clés Paillier jusqu'à 4096 bits :
//   n_squared est au plus 4096*2 bits = 1024 octets = 2048 caractères hex.
//   On prend 3072 avec une marge confortable.
// ============================================================================

/// Taille maximale d'un fichier de clés JSON en octets (32 Ko)
const MAX_KEY_FILE_BYTES: u64 = 32_768;

/// Longueur maximale d'un champ hexadécimal en caractères.
/// Couvre les clés jusqu'à 4096 bits (n_squared = 8192 bits = 2048 hex) + marge.
const MAX_HEX_FIELD_LEN: usize = 3_072;

// ============================================================================
// Structures JSON pour la sérialisation des clés
// ============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKeyJson {
    pub n:         String,
    pub g:         String,
    pub n_squared: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretKeyJson {
    pub lambda: String,
    pub mu:     String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyPairJson {
    pub public_key: PublicKeyJson,
    pub secret_key: SecretKeyJson,
}

// ============================================================================
// Conversion BigUint ↔ hexadécimal
// ============================================================================

pub fn biguint_to_hex(value: &BigUint) -> String {
    value.to_str_radix(16).to_uppercase()
}

/// Convertit une string hex en BigUint.
///
/// Vérifie la longueur du champ AVANT la conversion pour éviter une
/// allocation BigUint géante (vecteur DoS CPU).
///
/// Retourne :
///   Err(HexFieldTooLong)  si len > MAX_HEX_FIELD_LEN
///   Err(HexParseError)    si le contenu n'est pas un hex valide
pub fn hex_to_biguint(hex_str: &str) -> Result<BigUint, CryptoError> {
    if hex_str.len() > MAX_HEX_FIELD_LEN {
        return Err(CryptoError::HexFieldTooLong {
            actual:  hex_str.len(),
            maximum: MAX_HEX_FIELD_LEN,
        });
    }
    BigUint::from_str_radix(hex_str, 16)
        .map_err(|_| CryptoError::HexParseError)
}

// ============================================================================
// Conversion structures Rust → JSON
// ============================================================================

pub fn public_key_to_json(pk: &PublicKey) -> PublicKeyJson {
    PublicKeyJson {
        n:         biguint_to_hex(&pk.n),
        g:         biguint_to_hex(&pk.g),
        n_squared: biguint_to_hex(&pk.n_squared),
    }
}

pub fn secret_key_to_json(sk: &SecretKey) -> SecretKeyJson {
    SecretKeyJson {
        lambda: biguint_to_hex(&sk.lambda),
        mu:     biguint_to_hex(&sk.mu),
    }
}

pub fn keypair_to_json(kp: &KeyPair) -> KeyPairJson {
    KeyPairJson {
        public_key: public_key_to_json(&kp.public_key),
        secret_key: secret_key_to_json(&kp.secret_key),
    }
}

// ============================================================================
// Conversion JSON → structures Rust
// Validation de cohérence : n_squared == n*n vérifié au chargement.
// ============================================================================

pub fn json_to_public_key(json: &PublicKeyJson) -> Result<PublicKey, CryptoError> {
    let n         = hex_to_biguint(&json.n)?;
    let g         = hex_to_biguint(&json.g)?;
    let n_squared = hex_to_biguint(&json.n_squared)?;

    // Cohérence structurelle : protège contre les fichiers JSON corrompus/falsifiés
    if n_squared != &n * &n {
        return Err(CryptoError::KeyCoherenceError);
    }

    Ok(PublicKey { n, g, n_squared })
}

pub fn json_to_secret_key(json: &SecretKeyJson) -> Result<SecretKey, CryptoError> {
    Ok(SecretKey {
        lambda: hex_to_biguint(&json.lambda)?,
        mu:     hex_to_biguint(&json.mu)?,
    })
}

pub fn json_to_keypair(json: &KeyPairJson) -> Result<KeyPair, CryptoError> {
    Ok(KeyPair {
        public_key: json_to_public_key(&json.public_key)?,
        secret_key: json_to_secret_key(&json.secret_key)?,
    })
}

// ============================================================================
// Vérification de taille de fichier (DoS protection)
//
// Appelée avant fs::read_to_string pour éviter de charger un fichier de
// plusieurs Go en mémoire. La métadonnée est lue sans ouvrir le contenu.
// ============================================================================

fn check_file_size(filepath: &str) -> io::Result<()> {
    let meta = fs::metadata(filepath)?;
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Fichier de clés trop grand : {} octets (maximum autorisé : {} octets). \
                 Possible tentative DoS.",
                meta.len(),
                MAX_KEY_FILE_BYTES
            ),
        ));
    }
    Ok(())
}

// ============================================================================
// Sauvegarde JSON sur disque
// ============================================================================

pub fn save_keypair_json(kp: &KeyPair, filepath: &str) -> io::Result<()> {
    let json = serde_json::to_string_pretty(&keypair_to_json(kp))?;
    fs::write(filepath, json)?;
    Ok(())
}

pub fn save_public_key_json(pk: &PublicKey, filepath: &str) -> io::Result<()> {
    let json = serde_json::to_string_pretty(&public_key_to_json(pk))?;
    fs::write(filepath, json)?;
    Ok(())
}

pub fn save_secret_key_json(sk: &SecretKey, filepath: &str) -> io::Result<()> {
    let json = serde_json::to_string_pretty(&secret_key_to_json(sk))?;
    fs::write(filepath, json)?;
    Ok(())
}

// ============================================================================
// Chargement JSON depuis disque
// Vérification de la taille du fichier AVANT la lecture (protection DoS).
// ============================================================================

pub fn load_keypair_json(filepath: &str) -> io::Result<KeyPair> {
    check_file_size(filepath)?;
    let raw  = fs::read_to_string(filepath)?;
    let json: KeyPairJson = serde_json::from_str(&raw)?;
    json_to_keypair(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

pub fn load_public_key_json(filepath: &str) -> io::Result<PublicKey> {
    check_file_size(filepath)?;
    let raw  = fs::read_to_string(filepath)?;
    let json: PublicKeyJson = serde_json::from_str(&raw)?;
    json_to_public_key(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

pub fn load_secret_key_json(filepath: &str) -> io::Result<SecretKey> {
    check_file_size(filepath)?;
    let raw  = fs::read_to_string(filepath)?;
    let json: SecretKeyJson = serde_json::from_str(&raw)?;
    json_to_secret_key(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

// ============================================================================
// Utilitaires
// ============================================================================

pub fn key_file_exists(filepath: &str) -> bool {
    Path::new(filepath).exists()
}

pub fn ensure_keys_directory(dir_path: &str) -> io::Result<()> {
    if !Path::new(dir_path).exists() {
        fs::create_dir_all(dir_path)?;
    }
    Ok(())
}