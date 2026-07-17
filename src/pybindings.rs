// =========================================================
// pybindings.rs — Bindings Python (PyO3) pour paillier_crypto
//
// Compilé UNIQUEMENT avec `--features python` (utilisé par maturin) :
// n'affecte jamais les binaires `server`/`client`/`paillier_crypto`
// qui restent compilés sans dépendance à pyo3.
//
// Expose côté Python :
//   - Paillier : génération de clés, chiffrement, déchiffrement.
//   - PSI ExactMatch : les 4 phases (table, chiffrement CF, agrégation
//     serveur, déchiffrement + identification des patients communs).
//   - Un échantillon des 10 premiers chiffrés par bundle (H1/H2),
//     pour affichage DevOps côté frontend.
//   - Une erreur centralisée `PsiCryptoError`, pour que le backend
//     Python reçoive une exception propre plutôt qu'un crash.
//
// Toutes les BigUint traversent la frontière Python/Rust sous forme
// de chaînes HEXADÉCIMALES (pas de dépendance d'interop supplémentaire
// nécessaire ; Python peut les manipuler comme `int(x, 16)` si besoin).
//
// Note sur la robustesse : PyO3 intercepte AUTOMATIQUEMENT tout panic
// Rust survenant dans une fonction exposée et le convertit en exception
// Python (`pyo3_runtime.PanicException`) au lieu de faire planter le
// process hôte. Cette protection s'applique donc aussi aux chemins
// internes qui utilisent encore `.expect()` (non tous convertis en
// `Result<_, CryptoError>` à ce jour) — voir le README PyO3 pour le
// détail des fonctions déjà pleinement "Result-safe" vs celles qui
// s'appuient sur ce filet de sécurité PyO3.
// =========================================================

use std::borrow::Cow;
use std::collections::HashMap;

use num_bigint::BigUint;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

use crate::crypto_error::crypto_error::CryptoError;
use crate::hepseudo::{
    encode_pii, p_encrypt_det, parse_ddn, server_remask, ClientRecord, PatientPii, ServerResponse,
};
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::exactmatch::{
    load_ids_from_csv, phase1_build_table, phase2_prepare_ft, phase3_server_aggregate,
    phase4_decrypt_aggregate, AggResult, FtBundle, SparseTable,
};
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use crate::paillier::p_keygen::{p_keygen as raw_keygen, KeyPair, PublicKey};

// ---------------------------------------------------------
// Erreur centralisée exposée à Python (import : paillier_crypto.PsiCryptoError).
// Toute erreur crypto structurée (Result<_, CryptoError>) est convertie
// ici avec un message clair, plutôt que de laisser remonter un panic.
// ---------------------------------------------------------
create_exception!(paillier_crypto, PsiCryptoError, PyException);

fn to_py_err(e: CryptoError) -> PyErr {
    PsiCryptoError::new_err(e.to_string())
}

fn hex_to_biguint(field: &str, s: &str) -> PyResult<BigUint> {
    BigUint::parse_bytes(s.trim_start_matches("0x").as_bytes(), 16)
        .ok_or_else(|| PsiCryptoError::new_err(format!("Champ '{field}' : hexadecimal invalide ('{s}')")))
}

fn biguint_to_hex(v: &BigUint) -> String {
    format!("{:x}", v)
}

// =========================================================
// Key (de)serialization for persistence (bincode of big-endian bytes).
//
// Paillier-CF's PyKeyPair/PyPublicKey originally could not round-trip
// through storage. The Python backends generate the key in one HTTP
// request (keygen) and reload it in another (compute/decrypt), so the
// keypair MUST be serializable. Ported from the v0.4.0 module.
// =========================================================

#[derive(Serialize, Deserialize)]
struct PublicKeyBytes {
    pub_n: Vec<u8>,
    pub_g: Vec<u8>,
    pub_n_squared: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct KeyPairBytes {
    pub_n: Vec<u8>,
    pub_g: Vec<u8>,
    pub_n_squared: Vec<u8>,
    sec_lambda: Vec<u8>,
    sec_mu: Vec<u8>,
}

fn pk_to_bytes_helper(pk: &PublicKey) -> PyResult<Vec<u8>> {
    let data = PublicKeyBytes {
        pub_n: pk.n.to_bytes_be(),
        pub_g: pk.g.to_bytes_be(),
        pub_n_squared: pk.n_squared.to_bytes_be(),
    };
    bincode::serialize(&data).map_err(|e| PsiCryptoError::new_err(e.to_string()))
}

fn pk_from_bytes_helper(data: &[u8]) -> PyResult<PublicKey> {
    let pkb: PublicKeyBytes =
        bincode::deserialize(data).map_err(|e| PsiCryptoError::new_err(e.to_string()))?;
    Ok(PublicKey {
        n: BigUint::from_bytes_be(&pkb.pub_n),
        g: BigUint::from_bytes_be(&pkb.pub_g),
        n_squared: BigUint::from_bytes_be(&pkb.pub_n_squared),
    })
}

fn kp_to_bytes_helper(kp: &KeyPair) -> PyResult<Vec<u8>> {
    let data = KeyPairBytes {
        pub_n: kp.public_key.n.to_bytes_be(),
        pub_g: kp.public_key.g.to_bytes_be(),
        pub_n_squared: kp.public_key.n_squared.to_bytes_be(),
        sec_lambda: kp.secret_key.lambda.to_bytes_be(),
        sec_mu: kp.secret_key.mu.to_bytes_be(),
    };
    bincode::serialize(&data).map_err(|e| PsiCryptoError::new_err(e.to_string()))
}

fn kp_from_bytes_helper(data: &[u8]) -> PyResult<KeyPair> {
    let kpb: KeyPairBytes =
        bincode::deserialize(data).map_err(|e| PsiCryptoError::new_err(e.to_string()))?;
    let public_key = PublicKey {
        n: BigUint::from_bytes_be(&kpb.pub_n),
        g: BigUint::from_bytes_be(&kpb.pub_g),
        n_squared: BigUint::from_bytes_be(&kpb.pub_n_squared),
    };
    let secret_key = SecretKey {
        lambda: BigUint::from_bytes_be(&kpb.sec_lambda),
        mu: BigUint::from_bytes_be(&kpb.sec_mu),
    };
    Ok(KeyPair { public_key, secret_key })
}

// =========================================================
// Clé publique Paillier — sérialisable côté Python (n, g, n²).
// =========================================================

#[pyclass(name = "PublicKey")]
#[derive(Clone)]
pub struct PyPublicKey {
    pub(crate) inner: PublicKey,
}

#[pymethods]
impl PyPublicKey {
    /// Reconstruit une clé publique depuis des champs hexadécimaux
    /// (typiquement reçus sur le réseau côté Python).
    #[new]
    fn new(n_hex: &str, g_hex: &str, n_squared_hex: &str) -> PyResult<Self> {
        Ok(PyPublicKey {
            inner: PublicKey {
                n: hex_to_biguint("n", n_hex)?,
                g: hex_to_biguint("g", g_hex)?,
                n_squared: hex_to_biguint("n_squared", n_squared_hex)?,
            },
        })
    }

    #[getter]
    fn n(&self) -> String {
        biguint_to_hex(&self.inner.n)
    }
    #[getter]
    fn g(&self) -> String {
        biguint_to_hex(&self.inner.g)
    }
    #[getter]
    fn n_squared(&self) -> String {
        biguint_to_hex(&self.inner.n_squared)
    }
    #[getter]
    fn bits(&self) -> u64 {
        self.inner.n.bits()
    }

    /// Serialize the public key (n, g, n²) to bytes for storage/transport.
    fn to_bytes(&self) -> PyResult<Cow<'static, [u8]>> {
        Ok(Cow::Owned(pk_to_bytes_helper(&self.inner)?))
    }

    /// Rebuild a public key from bytes produced by `to_bytes`.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        Ok(PyPublicKey { inner: pk_from_bytes_helper(data)? })
    }

    fn __repr__(&self) -> String {
        format!("PyPublicKey(|n|={} bits)", self.inner.n.bits())
    }
}

// =========================================================
// Paire de clés Paillier complète (clé secrète incluse).
//
// La clé secrète (lambda, mu) reste dans l'objet Rust : Python ne peut
// appeler que `paillier_decrypt(...)` ou les fonctions de Phase 4
// dessus, pas la lire directement — sauf via `secret_key_hex()`,
// méthode explicitement marquée sensible (persistance uniquement,
// ne jamais transmettre sur le réseau).
// =========================================================

#[pyclass(name = "KeyPair")]
pub struct PyKeyPair {
    pub(crate) inner: KeyPair,
}

#[pymethods]
impl PyKeyPair {
    /// Return a copy of the public key. Exposed as a METHOD (`kp.public_key()`)
    /// to match the surface the Python backends already call.
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey { inner: self.inner.public_key.clone() }
    }

    /// ⚠️ SENSIBLE : expose lambda/mu (clé secrète complète) en hex.
    /// Réservé à la persistance locale côté H1. Ne jamais sérialiser
    /// ce résultat vers le serveur ou vers H2.
    fn secret_key_hex(&self) -> (String, String) {
        (
            biguint_to_hex(&self.inner.secret_key.lambda),
            biguint_to_hex(&self.inner.secret_key.mu),
        )
    }

    /// Serialize the full keypair (pk + sk) to bytes. Keep local to H1.
    fn to_bytes(&self) -> PyResult<Cow<'static, [u8]>> {
        Ok(Cow::Owned(kp_to_bytes_helper(&self.inner)?))
    }

    /// Rebuild a keypair from bytes produced by `to_bytes`.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        Ok(PyKeyPair { inner: kp_from_bytes_helper(data)? })
    }

    fn __repr__(&self) -> String {
        format!("PyKeyPair(|n|={} bits, sk=<local, non serialisee>)", self.inner.public_key.n.bits())
    }
}

// =========================================================
// Paillier — primitives directes.
// =========================================================

/// Génère une paire de clés Paillier. `bits` = taille de CHAQUE facteur
/// premier (|n| = 2*bits). Lève `PsiCryptoError` si bits < taille minimale.
#[pyfunction]
fn paillier_keygen(bits: u64) -> PyResult<PyKeyPair> {
    let kp = raw_keygen(bits).map_err(to_py_err)?;
    Ok(PyKeyPair { inner: kp })
}

/// Chiffre un message (entier en hexadécimal) sous la clé publique donnée.
/// Lève `PsiCryptoError` si le message est hors domaine (m >= n).
#[pyfunction]
fn paillier_encrypt(m_hex: &str, pk: &PyPublicKey) -> PyResult<String> {
    let m = hex_to_biguint("m", m_hex)?;
    let c = p_encrypt(&m, &pk.inner).map_err(to_py_err)?;
    Ok(biguint_to_hex(&c))
}

/// Déchiffre un chiffré (hexadécimal) avec la paire de clés (sk locale).
/// Lève `PsiCryptoError` si le chiffré est hors domaine (c >= n²).
#[pyfunction]
fn paillier_decrypt(c_hex: &str, kp: &PyKeyPair) -> PyResult<String> {
    let c = hex_to_biguint("c", c_hex)?;
    let m = p_decrypt(&c, &kp.inner.public_key, &kp.inner.secret_key).map_err(to_py_err)?;
    Ok(biguint_to_hex(&m))
}

// =========================================================
// PSI ExactMatch — Phase 1 : table binaire creuse.
// =========================================================

#[pyclass]
pub struct PySparseTable {
    pub(crate) inner: SparseTable,
}

#[pymethods]
impl PySparseTable {
    fn len(&self) -> usize {
        self.inner.len()
    }
    fn active_positions(&self) -> Vec<usize> {
        self.inner.active.iter().copied().collect()
    }
}

/// Phase 1 : construit la table binaire creuse à partir d'une liste
/// d'identifiants (email). `label` sert uniquement au log ("H1"/"H2").
#[pyfunction]
fn psi_phase1_build_table(label: &str, ids: Vec<String>) -> PySparseTable {
    PySparseTable { inner: phase1_build_table(label, &ids) }
}

/// Charge des identifiants depuis un CSV, colonne email auto-détectée
/// (ou imposée via `col_override`). Le chemin interne panique encore
/// (`.expect()`) en cas de fichier introuvable / colonne non détectée :
/// on capture explicitement ce panic ici pour renvoyer une
/// `PsiCryptoError` propre plutôt que de laisser planter le process Python.
#[pyfunction]
#[pyo3(signature = (path, col_override=None))]
fn psi_load_ids_from_csv(path: String, col_override: Option<String>) -> PyResult<Vec<String>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        load_ids_from_csv(&path, col_override.as_deref())
    }))
    .map_err(|payload| {
        let msg = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "Erreur inconnue lors du chargement du CSV".to_string());
        PsiCryptoError::new_err(msg)
    })
}

// =========================================================
// PSI ExactMatch — Phase 2 : bundle de chiffrés CF.
// =========================================================

#[pyclass]
pub struct PyFtBundle {
    pub(crate) inner: FtBundle,
}

#[pymethods]
impl PyFtBundle {
    fn len(&self) -> usize {
        self.inner.ft_by_pos.len()
    }

    /// Échantillon DevOps : les N premiers chiffrés triés par position,
    /// sous forme [(position, c0_hex, c1_hex), ...]. Chaque hôpital
    /// (H1/H2) produit des chiffrés TOUJOURS différents (aléa Paillier
    /// + masque propres à chaque appel) — propriété de sécurité
    /// sémantique de Paillier, utile à illustrer côté frontend.
    fn ciphertext_sample(&self, n: usize) -> Vec<(usize, String, String)> {
        let mut entries: Vec<(&usize, &(BigUint, BigUint))> = self.inner.ft_by_pos.iter().collect();
        entries.sort_by_key(|(pos, _)| **pos);
        entries
            .into_iter()
            .take(n)
            .map(|(pos, (c0, c1))| (*pos, biguint_to_hex(c0), biguint_to_hex(c1)))
            .collect()
    }

    /// Sérialise le bundle COMPLET pour transmission réseau côté Python.
    fn to_wire(&self) -> Vec<(usize, String, String)> {
        self.inner
            .ft_by_pos
            .iter()
            .map(|(&pos, (c0, c1))| (pos, biguint_to_hex(c0), biguint_to_hex(c1)))
            .collect()
    }

    /// Reconstruit un bundle depuis des données reçues du réseau.
    #[staticmethod]
    fn from_wire(entries: Vec<(usize, String, String)>) -> PyResult<Self> {
        let mut ft_by_pos = HashMap::with_capacity(entries.len());
        for (pos, c0_hex, c1_hex) in entries {
            let c0 = hex_to_biguint("c0", &c0_hex)?;
            let c1 = hex_to_biguint("c1", &c1_hex)?;
            ft_by_pos.insert(pos, (c0, c1));
        }
        Ok(PyFtBundle { inner: FtBundle { ft_by_pos } })
    }
}

/// Phase 2 : chiffre les positions actives sous la clé publique donnée
/// (celle de H1, que ce soit H1 ou H2 qui appelle cette fonction).
#[pyfunction]
fn psi_phase2_prepare_ft(label: &str, table: &PySparseTable, pk: &PyPublicKey) -> PyFtBundle {
    PyFtBundle { inner: phase2_prepare_ft(label, &table.inner, &pk.inner) }
}

// =========================================================
// PSI ExactMatch — Phase 3 : résultat agrégé (côté serveur).
// =========================================================

#[pyclass]
pub struct PyAggResult {
    pub(crate) inner: AggResult,
}

#[pymethods]
impl PyAggResult {
    /// Sérialise pour transmission réseau :
    /// (c0_agg_hex, [(position, enc_bprime_hex), ...]).
    fn to_wire(&self) -> (String, Vec<(usize, String)>) {
        (
            biguint_to_hex(&self.inner.c0_agg),
            self.inner.b_prime_enc.iter().map(|(pos, v)| (*pos, biguint_to_hex(v))).collect(),
        )
    }

    #[staticmethod]
    fn from_wire(c0_agg_hex: &str, b_prime_enc: Vec<(usize, String)>) -> PyResult<Self> {
        let c0_agg = hex_to_biguint("c0_agg", c0_agg_hex)?;
        let mut parsed = Vec::with_capacity(b_prime_enc.len());
        for (pos, v_hex) in b_prime_enc {
            parsed.push((pos, hex_to_biguint("enc_bp", &v_hex)?));
        }
        Ok(PyAggResult { inner: AggResult { c0_agg, b_prime_enc: parsed } })
    }
}

/// Phase 3 (serveur) : comparaison des positions + CF.Mul + agrégation.
/// Le serveur n'a besoin QUE de la clé publique de H1 (jamais sk) :
/// cette fonction est celle que le service "serveur" Python appellera.
#[pyfunction]
fn psi_phase3_server_aggregate(
    table1: &PySparseTable,
    table2: &PySparseTable,
    bd1: &PyFtBundle,
    bd2: &PyFtBundle,
    pk: &PyPublicKey,
) -> PyAggResult {
    PyAggResult {
        inner: phase3_server_aggregate(&table1.inner, &table2.inner, &bd1.inner, &bd2.inner, &pk.inner),
    }
}

// =========================================================
// PSI ExactMatch — Phase 4 : résultat final (H1 uniquement, sk locale).
// =========================================================

#[pyclass]
pub struct PyExactMatchResult {
    #[pyo3(get)]
    pub cardinal: usize,
    #[pyo3(get)]
    pub matched_ids: Vec<String>,
}

/// Phase 4 (H1, avec sk locale) : cardinal exact de l'intersection +
/// identification LOCALE des patients en commun (lookup en mémoire,
/// aucun calcul crypto ni aller-retour réseau supplémentaire).
#[pyfunction]
fn psi_phase4_decrypt_aggregate(
    label: &str,
    agg: &PyAggResult,
    own_bundle: &PyFtBundle,
    own_table: &PySparseTable,
    kp: &PyKeyPair,
) -> PyExactMatchResult {
    let r = phase4_decrypt_aggregate(label, &agg.inner, &own_bundle.inner, &own_table.inner, &kp.inner);
    PyExactMatchResult { cardinal: r.cardinal, matched_ids: r.matched_ids }
}

// =========================================================
// FHEnymisation — bindings (module hepseudo, porté de v0.4.0)
//
// Workflow distribué :
//   1. Client : py_fhenym_encrypt_csv(csv, pk) -> FhenymBatch
//      (PII chiffrés déterministes + colonnes métier en clair).
//   2. Serveur : py_fhenym_server_remask(batch, pk) -> FhenymResponseBatch
//      (FE_i = Enc_i^b mod n², un seul b pour le batch).
//   3. Client : py_fhenym_format_pseudonymes_csv(resp) -> CSV bytes
//      ("Pseudonyme Patient,<cols métier>").
// La sk n'est pas utilisée : les FE SONT les pseudonymes.
// =========================================================

#[derive(Serialize, Deserialize)]
struct ClientRecordBytes {
    enc_m: Vec<u8>,
    metier_vals: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct FhenymBatchBytes {
    records: Vec<ClientRecordBytes>,
    metier_names: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ServerResponseBytes {
    fe: Vec<u8>,
    metier_vals: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct FhenymResponseBatchBytes {
    responses: Vec<ServerResponseBytes>,
    metier_names: Vec<String>,
}

/// Client-side batch: deterministic-encrypted records + business column names.
#[pyclass(name = "FhenymBatch")]
pub struct PyFhenymBatch {
    pub records: Vec<ClientRecord>,
    pub metier_names: Vec<String>,
}

#[pymethods]
impl PyFhenymBatch {
    fn len(&self) -> usize {
        self.records.len()
    }
    fn metier_names(&self) -> Vec<String> {
        self.metier_names.clone()
    }

    fn to_bytes(&self) -> PyResult<Cow<'static, [u8]>> {
        let data = FhenymBatchBytes {
            records: self
                .records
                .iter()
                .map(|r| ClientRecordBytes {
                    enc_m: r.enc_m.to_bytes_be(),
                    metier_vals: r.metier_vals.clone(),
                })
                .collect(),
            metier_names: self.metier_names.clone(),
        };
        let v = bincode::serialize(&data).map_err(|e| PsiCryptoError::new_err(e.to_string()))?;
        Ok(Cow::Owned(v))
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<PyFhenymBatch> {
        let raw: FhenymBatchBytes =
            bincode::deserialize(data).map_err(|e| PsiCryptoError::new_err(e.to_string()))?;
        let records = raw
            .records
            .into_iter()
            .map(|r| ClientRecord {
                enc_m: BigUint::from_bytes_be(&r.enc_m),
                metier_vals: r.metier_vals,
            })
            .collect();
        Ok(PyFhenymBatch { records, metier_names: raw.metier_names })
    }

    fn __repr__(&self) -> String {
        format!("FhenymBatch({} records, {} colonnes metier)", self.records.len(), self.metier_names.len())
    }
}

/// Server-side batch: pseudonyms (FE) + business column names.
#[pyclass(name = "FhenymResponseBatch")]
pub struct PyFhenymResponseBatch {
    pub responses: Vec<ServerResponse>,
    pub metier_names: Vec<String>,
}

#[pymethods]
impl PyFhenymResponseBatch {
    fn len(&self) -> usize {
        self.responses.len()
    }
    fn metier_names(&self) -> Vec<String> {
        self.metier_names.clone()
    }

    fn to_bytes(&self) -> PyResult<Cow<'static, [u8]>> {
        let data = FhenymResponseBatchBytes {
            responses: self
                .responses
                .iter()
                .map(|r| ServerResponseBytes {
                    fe: r.fe.to_bytes_be(),
                    metier_vals: r.metier_vals.clone(),
                })
                .collect(),
            metier_names: self.metier_names.clone(),
        };
        let v = bincode::serialize(&data).map_err(|e| PsiCryptoError::new_err(e.to_string()))?;
        Ok(Cow::Owned(v))
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<PyFhenymResponseBatch> {
        let raw: FhenymResponseBatchBytes =
            bincode::deserialize(data).map_err(|e| PsiCryptoError::new_err(e.to_string()))?;
        let responses = raw
            .responses
            .into_iter()
            .map(|r| ServerResponse {
                fe: BigUint::from_bytes_be(&r.fe),
                metier_vals: r.metier_vals,
            })
            .collect();
        Ok(PyFhenymResponseBatch { responses, metier_names: raw.metier_names })
    }

    fn __repr__(&self) -> String {
        format!("FhenymResponseBatch({} pseudonymes, {} colonnes metier)", self.responses.len(), self.metier_names.len())
    }
}

// ── PII labels (identical to the ported client encoder) ──────────────────────
const FHENYM_LABEL_ID: &str = "id";
const FHENYM_LABEL_PRENOM: &str = "prenom";
const FHENYM_LABEL_NOM: &str = "nom";
const FHENYM_LABEL_AGE: &str = "age";
const FHENYM_LABEL_DDN: &str = "date de naissance";
const FHENYM_LABEL_NSS: &str = "numéro de sécurité sociale";

fn fhenym_normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

fn fhenym_is_pii(name: &str) -> bool {
    matches!(
        name,
        FHENYM_LABEL_ID | FHENYM_LABEL_PRENOM | FHENYM_LABEL_NOM
            | FHENYM_LABEL_AGE | FHENYM_LABEL_DDN | FHENYM_LABEL_NSS
    )
}

fn fhenym_detect_sep(header: &str) -> char {
    if header.contains(';') {
        ';'
    } else if header.contains('\t') {
        '\t'
    } else if header.contains('|') {
        '|'
    } else {
        ','
    }
}

/// Client — parse the CSV, encode each PII and deterministically encrypt under pk.
/// Required columns (case-insensitive): id, prenom, nom, age, date de naissance,
/// numéro de sécurité sociale. Every other column is kept as a business column.
#[pyfunction]
fn py_fhenym_encrypt_csv(csv_bytes: &[u8], pk: &PyPublicKey) -> PyResult<PyFhenymBatch> {
    let content = std::str::from_utf8(csv_bytes)
        .map_err(|e| PsiCryptoError::new_err(format!("CSV non UTF-8: {}", e)))?;

    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| PsiCryptoError::new_err("CSV vide (en-tete manquant)"))?;

    let sep = fhenym_detect_sep(header);
    let cols: Vec<&str> = header.split(sep).collect();
    let cols_norm: Vec<String> = cols.iter().map(|c| fhenym_normalize(c)).collect();

    let find = |label: &str| -> PyResult<usize> {
        cols_norm
            .iter()
            .position(|c| c == label)
            .ok_or_else(|| PsiCryptoError::new_err(format!("Colonne PII manquante : '{}'", label)))
    };

    let i_id = find(FHENYM_LABEL_ID)?;
    let i_prenom = find(FHENYM_LABEL_PRENOM)?;
    let i_nom = find(FHENYM_LABEL_NOM)?;
    let i_age = find(FHENYM_LABEL_AGE)?;
    let i_ddn = find(FHENYM_LABEL_DDN)?;
    let i_nss = find(FHENYM_LABEL_NSS)?;

    let metier: Vec<(usize, String)> = cols
        .iter()
        .enumerate()
        .filter(|(_, c)| !fhenym_is_pii(&fhenym_normalize(c)))
        .map(|(i, c)| (i, c.trim().to_string()))
        .collect();

    let metier_names: Vec<String> = metier.iter().map(|(_, n)| n.clone()).collect();

    let mut records: Vec<ClientRecord> = Vec::new();
    let mut line_no: u64 = 1;

    for line in lines {
        line_no += 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split(sep).collect();

        let get_field = |idx: usize, name: &str| -> PyResult<&str> {
            fields
                .get(idx)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    PsiCryptoError::new_err(format!("Ligne {}: champ '{}' absent ou vide", line_no, name))
                })
        };

        let id = get_field(i_id, FHENYM_LABEL_ID)?.to_string();
        let prenom = get_field(i_prenom, FHENYM_LABEL_PRENOM)?.to_string();
        let nom = get_field(i_nom, FHENYM_LABEL_NOM)?.to_string();

        let age_s = get_field(i_age, FHENYM_LABEL_AGE)?;
        let age: u8 = age_s
            .parse()
            .map_err(|_| PsiCryptoError::new_err(format!("Ligne {}: age invalide '{}'", line_no, age_s)))?;

        let ddn_s = get_field(i_ddn, FHENYM_LABEL_DDN)?;
        let ddn = parse_ddn(ddn_s).map_err(to_py_err)?;

        let nss = get_field(i_nss, FHENYM_LABEL_NSS)?.to_string();

        let metier_vals: Vec<String> = metier
            .iter()
            .map(|(i, _)| fields.get(*i).map(|s| s.trim().to_string()).unwrap_or_default())
            .collect();

        let pii = PatientPii { id, prenom, nom, age, ddn, nss };
        let m = encode_pii(&pii).map_err(to_py_err)?;
        let enc_m = p_encrypt_det(&m, &pk.inner).map_err(to_py_err)?;

        records.push(ClientRecord { enc_m, metier_vals });
    }

    Ok(PyFhenymBatch { records, metier_names })
}

/// Server — FE_i = Enc_i^b mod n², b drawn once for the batch.
#[pyfunction]
fn py_fhenym_server_remask(batch: &PyFhenymBatch, pk: &PyPublicKey) -> PyResult<PyFhenymResponseBatch> {
    let responses = server_remask(&batch.records, &pk.inner).map_err(to_py_err)?;
    Ok(PyFhenymResponseBatch { responses, metier_names: batch.metier_names.clone() })
}

/// Truncate an FE (hex) into a readable pseudonym: first 10 + '…' + last 5.
fn fhenym_truncate_pseudo(hex: &str) -> String {
    if hex.len() <= 15 {
        hex.to_string()
    } else {
        format!("{}…{}", &hex[..10], &hex[hex.len() - 5..])
    }
}

/// Client — build the final CSV from a FhenymResponseBatch.
/// Header: "Pseudonyme Patient,<col métier 1>,<col métier 2>,…".
#[pyfunction]
fn py_fhenym_format_pseudonymes_csv(batch: &PyFhenymResponseBatch) -> PyResult<Cow<'static, [u8]>> {
    let mut out = String::new();
    out.push_str("Pseudonyme Patient");
    for name in &batch.metier_names {
        out.push(',');
        out.push_str(name);
    }
    out.push('\n');

    for resp in &batch.responses {
        let hex = resp.fe.to_str_radix(16);
        let pseudo = fhenym_truncate_pseudo(&hex);
        out.push_str(&pseudo);
        for v in &resp.metier_vals {
            out.push(',');
            out.push_str(v);
        }
        out.push('\n');
    }
    Ok(Cow::Owned(out.into_bytes()))
}

/// Full single-process pipeline (tests / worker-does-everything).
#[pyfunction]
fn py_fhenym_run_full(csv_bytes: &[u8], pk: &PyPublicKey) -> PyResult<Cow<'static, [u8]>> {
    let batch = py_fhenym_encrypt_csv(csv_bytes, pk)?;
    let responses = py_fhenym_server_remask(&batch, pk)?;
    py_fhenym_format_pseudonymes_csv(&responses)
}

// =========================================================
// Déclaration du module Python : `import paillier_crypto`
// =========================================================

#[pymodule]
fn paillier_crypto(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("PsiCryptoError", py.get_type_bound::<PsiCryptoError>())?;

    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PySparseTable>()?;
    m.add_class::<PyFtBundle>()?;
    m.add_class::<PyAggResult>()?;
    m.add_class::<PyExactMatchResult>()?;
    m.add_class::<PyFhenymBatch>()?;
    m.add_class::<PyFhenymResponseBatch>()?;

    m.add_function(wrap_pyfunction!(paillier_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(paillier_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(paillier_decrypt, m)?)?;

    m.add_function(wrap_pyfunction!(psi_load_ids_from_csv, m)?)?;
    m.add_function(wrap_pyfunction!(psi_phase1_build_table, m)?)?;
    m.add_function(wrap_pyfunction!(psi_phase2_prepare_ft, m)?)?;
    m.add_function(wrap_pyfunction!(psi_phase3_server_aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(psi_phase4_decrypt_aggregate, m)?)?;

    m.add_function(wrap_pyfunction!(py_fhenym_encrypt_csv, m)?)?;
    m.add_function(wrap_pyfunction!(py_fhenym_server_remask, m)?)?;
    m.add_function(wrap_pyfunction!(py_fhenym_format_pseudonymes_csv, m)?)?;
    m.add_function(wrap_pyfunction!(py_fhenym_run_full, m)?)?;

    Ok(())
}
