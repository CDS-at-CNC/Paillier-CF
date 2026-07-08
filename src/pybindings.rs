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

use std::collections::HashMap;

use num_bigint::BigUint;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

use crate::crypto_error::crypto_error::CryptoError;
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
// Clé publique Paillier — sérialisable côté Python (n, g, n²).
// =========================================================

#[pyclass]
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

#[pyclass]
pub struct PyKeyPair {
    pub(crate) inner: KeyPair,
}

#[pymethods]
impl PyKeyPair {
    #[getter]
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
// Déclaration du module Python : `import paillier_crypto`
// =========================================================

#[pymodule]
fn paillier_crypto(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("PsiCryptoError", py.get_type::<PsiCryptoError>())?;

    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PySparseTable>()?;
    m.add_class::<PyFtBundle>()?;
    m.add_class::<PyAggResult>()?;
    m.add_class::<PyExactMatchResult>()?;

    m.add_function(wrap_pyfunction!(paillier_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(paillier_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(paillier_decrypt, m)?)?;

    m.add_function(wrap_pyfunction!(psi_load_ids_from_csv, m)?)?;
    m.add_function(wrap_pyfunction!(psi_phase1_build_table, m)?)?;
    m.add_function(wrap_pyfunction!(psi_phase2_prepare_ft, m)?)?;
    m.add_function(wrap_pyfunction!(psi_phase3_server_aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(psi_phase4_decrypt_aggregate, m)?)?;

    Ok(())
}
