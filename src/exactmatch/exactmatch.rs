// =========================================================
// ExactMatch — PSI asymétrique (cardinal d'intersection)
// via Catalano-Fiore (1 niveau de Mul).
//
// MODÈLE MONO-CLÉ ASYMÉTRIQUE (PoC / MVP) :
//   - H1 génère l'UNIQUE paire de clés Paillier (pk, sk).
//   - H1 partage pk au serveur et à H2 ; sk ne quitte jamais H1.
//   - H1 et H2 chiffrent leurs données sous pk (clé de H1).
//   - Le serveur fait CF.Mul sous pk (clé de H1).
//   - Seul H1 déchiffre le résultat  ->  asymétrie.
//
// TABLE DE CORRESPONDANCE BINAIRE :
//   t[i] = 1  si l'indice i est présent (NSS haché -> position i)
//   t[i] = 0  sinon.
//   Représentation creuse : on ne stocke QUE les positions à 1
//   (toute position absente vaut implicitement 0).
//
// (Sécurité volontairement mise de côté pour ce PoC.)
// =========================================================

use num_bigint::{BigUint, RandBigInt};
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use sha2::{Digest, Sha256};
use crate::paillier::math::mod_inverse;

use crate::paillier::p_keygen::PublicKey;
use crate::fiore_catalano::cf_mul::cf_mul::cf_mul;
use crate::fiore_catalano::cf_mul_dec::cf_mul_dec::cf_mul_dec;
use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_keygen::p_keygen::p_keygen;
use crate::KeyPair;

// ---------------------------------------------------------
// Constantes
// ---------------------------------------------------------

// DOMAINE DENSE (Option 2 corrigée) : M = 2^14 = 16 384.
//
// Le domaine doit rester PETIT pour permettre l'envoi d'une entrée
// chiffrée pour CHAQUE position (0 ou 1), et pas seulement pour les
// positions actives : c'est ce qui empêche le serveur de déduire les
// positions communes à partir des clés reçues (cf. correctif sécurité).
// Compromis : collisions internes ~ n²/(2M) (paradoxe des anniversaires).
// ⚠️ À dimensionner selon n max attendu ; 16 384 convient pour n ≲ 1000.
pub const HASH_BITS:  usize = 14;
pub const TABLE_SIZE: usize = 1 << HASH_BITS;

// ---------------------------------------------------------
// Types alias
// ---------------------------------------------------------

/// CF Première Forme : (c0, c1)
///   c0 = m - b mod n,   c1 = Enc_pk(b)
pub type CfFst = (BigUint, BigUint);

/// CF Seconde Forme : (C0, C1, C2)
pub type CfSnd = (BigUint, BigUint, BigUint);

// ---------------------------------------------------------
// Table binaire creuse : `active` = ensemble des positions à 1.
// `position_to_id` conserve l'identifiant original (email) de
// chaque position, pour pouvoir ensuite IDENTIFIER les patients
// en commun (pas seulement compter le cardinal).
// ---------------------------------------------------------

pub struct SparseTable {
    pub active: HashSet<usize>,
    pub position_to_id: HashMap<usize, String>,
}

impl SparseTable {
    /// Construit t[] à partir d'une liste d'identifiants (email) : t[h(id)] = 1.
    pub fn build(ids: &[String]) -> Self {
        let mut active = HashSet::new();
        let mut position_to_id = HashMap::with_capacity(ids.len());
        for id in ids {
            let pos = simple_hash(id);
            active.insert(pos);
            position_to_id.insert(pos, id.clone()); // écrase en cas de collision (rare)
        }
        SparseTable { active, position_to_id }
    }

    /// t[pos] : renvoie true si la position vaut 1 (présence).
    pub fn is_present(&self, pos: usize) -> bool {
        self.active.contains(&pos)
    }

    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// Positions à 1 communes aux deux tables (t1[i] = t2[i] = 1).
    /// Comparaison EN CLAIR côté serveur (compromis assumé : vitesse
    /// et identification des patients communs, au prix de la
    /// confidentialité de l'ensemble d'intersection vis-à-vis du serveur).
    pub fn common_positions(&self, other: &SparseTable) -> Vec<usize> {
        let (small, big) = if self.active.len() <= other.active.len() {
            (&self.active, &other.active)
        } else {
            (&other.active, &self.active)
        };
        small.iter().filter(|p| big.contains(p)).copied().collect()
    }
}

// ---------------------------------------------------------
// Bundle : Ft chiffrés sous l'UNIQUE clé publique (celle de H1).
//   ft_by_pos[i] = CF.Enc(1, b_i)  pour chaque position i à 1.
// ---------------------------------------------------------

pub struct FtBundle {
    pub ft_by_pos: HashMap<usize, CfFst>,
}

// ---------------------------------------------------------
// Résultat AGRÉGÉ envoyé par le serveur à H1 (Option 2).
//
//   c0_agg       = ∏_{p ∈ commun} C0_p  mod N²   (un seul chiffré Paillier)
//   b_prime_enc  = [ (p, Enc(b'_p)) ]  pour chaque position commune p
//                  (c'est le c1' de H2 ; « H2 envoie Enc(b') à H1 »,
//                   relayé par le serveur qui le possède déjà).
//
// H1 reconstruit ensuite  E_cross = ∏ Enc(b'_p)^{b_p} = Enc(Σ b_p·b'_p)
// et obtient  cardinal = Dec(c0_agg) + Dec(E_cross)  mod N.
// ---------------------------------------------------------

pub struct AggResult {
    pub c0_agg:      BigUint,
    pub b_prime_enc: Vec<(usize, BigUint)>,
}

// ---------------------------------------------------------
// Hash (PoC — à remplacer par SHA-256/BLAKE3 + PRF à clé).
// ---------------------------------------------------------

pub fn simple_hash(s: &str) -> usize {
    let mut h: u32 = 0;
    for ch in s.chars() {
        h = h.wrapping_shl(7).wrapping_sub(h).wrapping_add(ch as u32);
    }
    (h as usize) & (TABLE_SIZE - 1)
}

// ---------------------------------------------------------
// Chargement CSV — détection AUTOMATIQUE de la colonne email.
//
// Les fichiers CRM n'utilisent pas tous le même intitulé de colonne
// pour l'adresse email. On normalise chaque en-tête (minuscule,
// accents retirés, ponctuation retirée) puis on compare à une liste
// de libellés connus. En dernier recours, on retient tout en-tête
// contenant "mail" / "courriel" / "electronique". Un nom de colonne
// exact peut aussi être imposé via `col_override`.
// ---------------------------------------------------------

fn normalize_header(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' => 'i',
            'ô' | 'ö' => 'o',
            'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            other => other,
        })
        .filter(|c| c.is_alphanumeric())
        .collect()
}

const EMAIL_HEADER_CANDIDATES: &[&str] = &[
    "email", "mail", "emailaddress", "mailaddress",
    "adressemail", "adresseemail", "adressemel", "mel",
    "adresseelectronique", "adressecourriel", "courriel",
    "emailaddr", "adressemailclient", "contactemail",
];

/// Cherche la colonne email par nom connu, sinon par mot-clé partiel.
pub fn find_email_column(header: &[&str]) -> Option<usize> {
    let normalized: Vec<String> = header.iter().map(|h| normalize_header(h)).collect();

    // 1) Correspondance exacte avec un libellé connu.
    for (i, h) in normalized.iter().enumerate() {
        if EMAIL_HEADER_CANDIDATES.contains(&h.as_str()) {
            return Some(i);
        }
    }
    // 2) Repli : en-tête contenant un mot-clé email/courriel/électronique.
    for (i, h) in normalized.iter().enumerate() {
        if h.contains("mail") || h.contains("courriel")
            || (h.contains("adresse") && h.contains("electronique"))
        {
            return Some(i);
        }
    }
    None
}

/// Charge les identifiants (email) depuis un CSV, colonne auto-détectée
/// (ou imposée via `col_override`, comparaison insensible à la casse/accents).
pub fn load_ids_from_csv(path: &str, col_override: Option<&str>) -> Vec<String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path)
        .unwrap_or_else(|e| panic!("Impossible d'ouvrir {} : {}", path, e));
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let header_line = lines.next().expect("Fichier vide").expect("Erreur lecture");
    let cols: Vec<&str> = header_line.split(',').collect();

    let col_idx = match col_override {
        Some(name) => {
            let target = normalize_header(name);
            cols.iter().position(|c| normalize_header(c) == target)
                .unwrap_or_else(|| panic!(
                    "Colonne '{}' introuvable. En-têtes disponibles : {:?}", name, cols
                ))
        }
        None => find_email_column(&cols).unwrap_or_else(|| panic!(
            "Impossible de détecter automatiquement la colonne email parmi {:?}. \
             Utilisez --email-col <nom_exact_de_colonne> pour la préciser.", cols
        )),
    };

    println!(
        "  [CSV] Colonne d'identification : \"{}\" (index {})",
        cols[col_idx].trim(), col_idx
    );

    lines
        .filter_map(|line| {
            let line = line.ok()?;
            let val = line.split(',').nth(col_idx)?.trim().to_lowercase(); // email: casse insensible
            if val.is_empty() { None } else { Some(val) }
        })
        .collect()
}

// ---------------------------------------------------------
// Phase 0 — KeyGen (exécutée UNIQUEMENT par H1)
// ---------------------------------------------------------

pub fn phase0_keygen(label: &str, bits: u64) -> KeyPair {
    println!("  [Phase 0] {} : generation de l'UNIQUE paire de cles ({} bits)...", label, bits);
    let t = Instant::now();
    let kp = p_keygen(bits).expect("p_keygen a echoue");
    println!("  [Phase 0] {} : cles generees en {:.3?}", label, t.elapsed());
    kp
}

// ---------------------------------------------------------
// Phase 1 — Table binaire creuse
// ---------------------------------------------------------

pub fn phase1_build_table(label: &str, ids: &[String]) -> SparseTable {
    println!(
        "  [Phase 1] {} : {} identifiant(s) (email), TABLE_SIZE=2^{}...",
        label, ids.len(), HASH_BITS
    );
    let table = SparseTable::build(ids);
    println!("  [Phase 1] {} : {} position(s) a 1.", label, table.len());
    table
}

// ---------------------------------------------------------
// Helper : CF.Enc(value, b) = ( (value - b) mod n, Enc_pk(b) ) sous pk.
// value ∈ {0, 1} : 1 = position active, 0 = position inactive (table dense).
// ---------------------------------------------------------

fn make_ft_for_value(value: u32, b: &BigUint, pk: &PublicKey) -> CfFst {
    let n     = &pk.n;
    let b_mod = b % n;
    let v     = BigUint::from(value);
    let c0    = (n + &v - &b_mod) % n; // (value - b) mod n, sans dépassement
    let c1    = p_encrypt(&b_mod, pk).expect("p_encrypt(b) a echoue");
    (c0, c1)
}

// ---------------------------------------------------------
// Phase 2 — Préparation des Ft sous l'UNIQUE clé publique pk.
//
// VARIANTE CREUSE (rapide) : seules les positions ACTIVES sont
// envoyées — pas de remplissage dense du domaine. Compromis assumé :
// le serveur verra les positions en clair en Phase 3 (comparaison
// d'ensembles), ce qui lui permet de déduire l'intersection — mais
// permet en retour un calcul beaucoup plus rapide et l'identification
// des patients en commun (cf. Phase 4).
//
// Appelée par H1 (pk = sa propre clé publique) ET par H2
// (pk = clé publique de H1, reçue via le serveur en Phase 0b).
// ---------------------------------------------------------

pub fn phase2_prepare_ft(
    label: &str,
    table: &SparseTable,
    pk:    &PublicKey,
) -> FtBundle {
    println!(
        "  [Phase 2] {} : preparation Ft pour {} position(s) active(s) (sous pk de H1)...",
        label, table.len()
    );

    let mut rng = OsRng;
    let mut ft: HashMap<usize, CfFst> = HashMap::with_capacity(table.len());

    for &pos in table.active.iter() {
        let b = rng.gen_biguint_below(&pk.n);
        ft.insert(pos, make_ft_for_value(1, &b, pk));
    }

    println!("  [Phase 2] {} : {} Ft prets.", label, ft.len());
    FtBundle { ft_by_pos: ft }
}

// ---------------------------------------------------------
// Phase 3 — Serveur : CF.Mul sur les positions communes,
// sous l'UNIQUE clé publique pk (celle de H1).
//
// Pour chaque position i à 1 dans les DEUX tables :
//   CF.Mul( Ft_H1[i], Ft_H2[i], pk )  encode  t1[i] * t2[i] = 1.
// Le serveur n'a que pk (pas de sk) : il ne peut pas déchiffrer.
// ---------------------------------------------------------

pub fn phase3_server_compute(
    table1: &SparseTable,
    table2: &SparseTable,
    bd1:    &FtBundle,
    bd2:    &FtBundle,
    pk:     &PublicKey,
) -> Vec<CfSnd> {
    println!("  [Phase 3] Serveur : CF.Mul sur les positions communes (clé de H1)...");
    let t_start = Instant::now();

    let common = table1.common_positions(table2);
    println!("  [Phase 3] {} position(s) commune(s).", common.len());

    let mut out: Vec<CfSnd> = Vec::with_capacity(common.len());

    for pos in common.iter().copied() {
        let ft1 = bd1.ft_by_pos.get(&pos)
            .expect("H1 Ft manquant pour une position commune");
        let ft2 = bd2.ft_by_pos.get(&pos)
            .expect("H2 Ft manquant pour une position commune");
        out.push(cf_mul(ft1, ft2, pk).expect("cf_mul a echoue"));
    }

    println!(
        "  [Phase 3] termine en {:.3?} ({} CF.Mul, une seule cle).",
        t_start.elapsed(), out.len()
    );

    out
}

// ---------------------------------------------------------
// Phase 4 — H1 : Dec2 sur chaque triplet + somme = cardinal.
// (Exécutée UNIQUEMENT par H1, avec sa clé secrète.)
// ---------------------------------------------------------

pub fn phase4_decrypt_and_count(label: &str, cts: &[CfSnd], kp: &KeyPair) -> usize {
    println!("  [Phase 4] {} : Dec2 ({} triplets)...", label, cts.len());
    let t_start = Instant::now();

    let mut sum = BigUint::from(0u32);
    for ct in cts {
        let m = cf_mul_dec(ct, &kp.public_key, &kp.secret_key)
            .expect("cf_mul_dec a echoue");
        sum += m;
    }

    let count = sum.to_u64_digits().last().copied().unwrap_or(0) as usize;

    println!(
        "  [Phase 4] {} : termine en {:.3?}  ->  cardinal = {}",
        label, t_start.elapsed(), count
    );

    count
}

// =========================================================
//   VARIANTE AGRÉGÉE (Option 2) — CREUSE, positions en clair
//
// Compromis assumé (demandé explicitement) : le serveur compare
// les positions EN CLAIR (`common_positions`) pour déterminer
// l'intersection — rapide, et permet à H1 d'identifier ensuite
// LES PATIENTS en commun (pas seulement leur nombre), via une
// recherche locale position -> identifiant (email) dans sa propre
// table. Le calcul du cardinal via Paillier/CF reste malgré tout
// utilisé (2 déchiffrements), conformément à la construction du
// rapport de référence.
// =========================================================

// ---------------------------------------------------------
// Phase 3 (agrégée) — Serveur : CF.Mul sur les positions COMMUNES
// (déterminées en clair), puis agrégation en un seul chiffré C0.
//
//   (C0_p, _, C2_p) = CF.Mul( Ft_H1[p], Ft_H2[p], pk )
//   avec  C0_p = Enc(c0·c0' + b'·c0 + b·c0')  et  C2_p = Enc(b'_p).
// Le serveur agrège :  c0_agg = ∏_p C0_p  mod N²  (positions communes)
// et collecte les Enc(b'_p) pour le terme croisé côté H1.
// Le serveur n'a pas sk : il ne déchiffre rien.
// ---------------------------------------------------------

pub fn phase3_server_aggregate(
    table1: &SparseTable,
    table2: &SparseTable,
    bd1:    &FtBundle,
    bd2:    &FtBundle,
    pk:     &PublicKey,
) -> AggResult {
    let t_start = Instant::now();

    let common = table1.common_positions(table2);

    let n2 = &pk.n_squared;
    let mut c0_agg = BigUint::from(1u32); // élément neutre du produit mod N²
    let mut b_prime_enc: Vec<(usize, BigUint)> = Vec::with_capacity(common.len());

    for pos in common.iter().copied() {
        let ft1 = bd1.ft_by_pos.get(&pos)
            .expect("H1 Ft manquant pour une position commune");
        let ft2 = bd2.ft_by_pos.get(&pos)
            .expect("H2 Ft manquant pour une position commune");

        // CF.Mul -> (C0, C1, C2) ; on garde C0 (à agréger) et C2 = Enc(b'_p).
        let (c0, _c1, c2) = cf_mul(ft1, ft2, pk).expect("cf_mul a echoue");

        c0_agg = (c0_agg * c0) % n2;
        b_prime_enc.push((pos, c2));
    }

    println!(
        "  [Phase 3] termine en {:.3?} — 1 chiffré agrégé + {} Enc(b').",
        t_start.elapsed(), b_prime_enc.len()
    );

    AggResult { c0_agg, b_prime_enc }
}

// ---------------------------------------------------------
// Résultat de la Phase 4 : cardinal EXACT + identifiants (email)
// des patients en commun, retrouvés LOCALEMENT par H1 (aucune
// information supplémentaire requise du serveur : la liste des
// positions communes est déjà portée par `agg.b_prime_enc`).
// ---------------------------------------------------------

pub struct ExactMatchResult {
    pub cardinal:    usize,
    pub matched_ids: Vec<String>,
}

// ---------------------------------------------------------
// Phase 4 (agrégée) — H1 (avec sk locale).
//
//   1) E_cross = ∏_p Enc(b'_p)^{b_p}  mod N²   = Enc(Σ_p b_p·b'_p)
//      où b_p est retrouvé depuis le PROPRE bundle de H1 :
//      b_p = (1 − c0_p) mod N (positions communes -> toujours actives
//      côté H1, donc value=1).
//   2) cardinal = Dec(c0_agg) + Dec(E_cross)  mod N     (2 déchiffrements)
//   3) identification : pour chaque position commune, lookup local
//      dans own_table.position_to_id (aucun calcul cryptographique
//      supplémentaire, aucun aller-retour réseau).
// ---------------------------------------------------------

pub fn phase4_decrypt_aggregate(
    label:       &str,
    agg:         &AggResult,
    own_bundle:  &FtBundle,
    own_table:   &SparseTable,
    kp:          &KeyPair,
) -> ExactMatchResult {
    println!(
        "  [Phase 4] {} : reconstruction terme croisé ({} position(s) commune(s)) + 2 Dec...",
        label, agg.b_prime_enc.len()
    );
    let t_start = Instant::now();

    let n  = &kp.public_key.n;
    let n2 = &kp.public_key.n_squared;

    // 1) Terme croisé par exponentiation homomorphe.
    let mut e_cross = BigUint::from(1u32);
    for (pos, enc_bp) in agg.b_prime_enc.iter() {
        let (c0_self, _c1_self) = own_bundle.ft_by_pos.get(pos)
            .expect("H1 : c0 manquant pour une position commune (bundle local)");
        let value_self = if own_table.is_present(*pos) { 1u32 } else { 0u32 };
        let b_self = (n + &BigUint::from(value_self) - (c0_self % n)) % n;
        e_cross = (e_cross * enc_bp.modpow(&b_self, n2)) % n2;
    }

    // 2) Deux déchiffrements Paillier seulement.
    let m0 = p_decrypt(&agg.c0_agg, &kp.public_key, &kp.secret_key)
        .expect("p_decrypt(c0_agg) a echoue");
    let m_cross = p_decrypt(&e_cross, &kp.public_key, &kp.secret_key)
        .expect("p_decrypt(e_cross) a echoue");

    let cardinal_big = (m0 + m_cross) % n;
    let cardinal = cardinal_big.to_u64_digits().last().copied().unwrap_or(0) as usize;

    // 3) Identification LOCALE des patients communs (lookup, pas de crypto).
    let matched_ids: Vec<String> = agg.b_prime_enc.iter()
        .filter_map(|(pos, _)| own_table.position_to_id.get(pos).cloned())
        .collect();

    println!(
        "  [Phase 4] {} : termine en {:.3?} (2 Dec Paillier)  ->  cardinal = {}, {} identifiant(s) retrouve(s)",
        label, t_start.elapsed(), cardinal, matched_ids.len()
    );

    ExactMatchResult { cardinal, matched_ids }
}

// =========================================================
//   VARIANTE "EXACT MATCH" — bucket + comparaison exacte
//
// CORRECTIF DE FOND : dans les variantes précédentes (creuse ou
// dense), un match n'était détecté que par COÏNCIDENCE DE POSITION
// (t1[p]=t2[p]=1), sans jamais vérifier qu'il s'agit du MÊME
// PATIENT. Deux identifiants DIFFÉRENTS tombant par hasard sur la
// même position comptaient comme un match — un taux de faux
// positifs de l'ordre de n_H1×n_H2/M, du même ordre de grandeur
// que l'intersection elle-même pour n de quelques milliers.
//
// Ici, chaque position porte l'IDENTITÉ EXACTE (SHA-256 complet,
// 256 bits) au lieu d'un simple bit de présence. Le serveur calcule,
// pour chaque bucket p, un TEST D'ÉGALITÉ AVEUGLÉ homomorphe :
//
//     D_p = Enc( r_p · (m1_p − m2_p) mod N )
//
// avec r_p ALÉATOIRE et SECRET, choisi par le SERVEUR (ni H1 ni H2
// ne le connaissent) :
//   - m1_p == m2_p  (même identité)      => D_p = Enc(0)
//   - m1_p != m2_p  (buckets différents) => D_p = Enc(alea), non nul
//     avec une probabilité écrasante (négligeable seulement si
//     r_p divise accidentellement N, probabilité ~2^-500).
//
// H1 ne déchiffre QUE les buckets où SA PROPRE table est active
// (il le sait localement, sans information du serveur) : cela
// exclut automatiquement le cas "les deux vides" (0-0=0), et ne
// coûte que n_H1 déchiffrements — pas les M du domaine entier.
//
// Résidu de collision restant (mineur, gérable) : si DEUX identi-
// fiants du MÊME côté tombent sur le MÊME bucket, un seul est
// conservé (écrasement) — l'autre est silencieusement perdu (faux
// négatif, pas faux positif). Probabilité ≈ n²/(2·BUCKET_DOMAIN),
// à contrôler en dimensionnant BUCKET_DOMAIN par rapport à n.
// =========================================================

pub const BUCKET_BITS:   usize = 16;
pub const BUCKET_DOMAIN: usize = 1 << BUCKET_BITS;

/// Valeur d'identité à forte entropie : SHA-256 complet (256 bits).
/// Très largement < N (Paillier ≥ 1024 bits ici) : la probabilité
/// que deux identifiants DIFFÉRENTS produisent la même valeur est
/// ≈ 2^-128 (paradoxe des anniversaires sur 256 bits), négligeable.
pub fn identity_value(s: &str) -> BigUint {
    let digest = Sha256::digest(s.as_bytes());
    BigUint::from_bytes_be(&digest)
}

/// Table de buckets : position -> valeur d'identité exacte (SHA-256).
/// Au plus UNE entrée par bucket (cf. note sur le résidu de collision).
pub struct BucketTable {
    pub values: HashMap<usize, BigUint>,
}

impl BucketTable {
    pub fn build(nss_list: &[String]) -> Self {
        let modulus = BigUint::from(BUCKET_DOMAIN as u64);
        let mut values = HashMap::with_capacity(nss_list.len());
        for nss in nss_list {
            let v = identity_value(nss);
            // Bucket = derniers BUCKET_BITS bits de l'identité.
            let bucket = (&v % &modulus)
                .to_u64_digits().first().copied().unwrap_or(0) as usize;
            values.insert(bucket, v); // écrase en cas de collision (documenté)
        }
        BucketTable { values }
    }

    pub fn is_present(&self, pos: usize) -> bool {
        self.values.contains_key(&pos)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }
}

/// Bundle envoyé par H1 ou H2 : Enc_pk(m_p) pour CHAQUE bucket
/// [0, BUCKET_DOMAIN) — dense, comme les variantes précédentes,
/// pour que le serveur ne puisse jamais distinguer les buckets
/// actifs des buckets vides.
pub struct EncBundle {
    pub enc_by_pos: HashMap<usize, BigUint>,
}

// ---------------------------------------------------------
// Phase 1 (exact-match) — construction de la table de buckets.
// ---------------------------------------------------------

pub fn phase1_build_bucket_table(label: &str, nss_list: &[String]) -> BucketTable {
    println!(
        "  [Phase 1] {} : {} NSS -> table de buckets (domaine={} slots, identité=SHA-256/256 bits)...",
        label, nss_list.len(), BUCKET_DOMAIN
    );
    let table = BucketTable::build(nss_list);
    let dropped = nss_list.len().saturating_sub(table.len());
    if dropped > 0 {
        println!(
            "  [Phase 1] {} : {} collision(s) interne(s) de bucket (item(s) perdu(s), résidu mineur).",
            label, dropped
        );
    }
    println!("  [Phase 1] {} : {} bucket(s) actif(s).", label, table.len());
    table
}

// ---------------------------------------------------------
// Phase 2 (exact-match) — chiffrement Paillier DENSE (pas de CF ici :
// une comparaison d'égalité ne nécessite que le chiffrement de base
// + l'homomorphie additive de Paillier, pas de multiplication CF).
// ---------------------------------------------------------

pub fn phase2_prepare_enc_bundle(
    label: &str,
    table: &BucketTable,
    pk:    &PublicKey,
) -> EncBundle {
    println!(
        "  [Phase 2] {} : chiffrement Paillier dense sur {} buckets ({} actifs, sous pk de H1)...",
        label, BUCKET_DOMAIN, table.len()
    );

    let zero = BigUint::from(0u32);
    let mut enc: HashMap<usize, BigUint> = HashMap::with_capacity(BUCKET_DOMAIN);

    for pos in 0..BUCKET_DOMAIN {
        let m = table.values.get(&pos).unwrap_or(&zero);
        let c = p_encrypt(m, pk).expect("p_encrypt(m_p) a echoue");
        enc.insert(pos, c);
    }

    println!("  [Phase 2] {} : {} ciphertexts prets (domaine dense, identité chiffrée).", label, enc.len());
    EncBundle { enc_by_pos: enc }
}

// ---------------------------------------------------------
// Phase 3 (exact-match) — Serveur : test d'égalité aveuglé.
//
// Pour CHAQUE bucket p du domaine (jamais seulement les communs) :
//   diff_p = Enc(m1_p) · Enc(m2_p)^{-1}  mod N²     (soustraction Paillier)
//   D_p    = diff_p ^ r_p                mod N²     (mise à l'échelle par r_p ALÉATOIRE, secret)
// Le serveur ne détient pas sk : il ne peut jamais apprendre m1_p, m2_p
// ni leur différence en clair — seulement manipuler les chiffrés.
// ---------------------------------------------------------

pub fn phase3_server_blind_diff(
    bd1: &EncBundle,
    bd2: &EncBundle,
    pk:  &PublicKey,
) -> Vec<(usize, BigUint)> {
    println!(
        "  [Phase 3] Serveur : test d'egalite aveugle sur {} buckets (clé de H1)...",
        BUCKET_DOMAIN
    );
    let t_start = Instant::now();

    let n  = &pk.n;
    let n2 = &pk.n_squared;
    let mut rng = OsRng;
    let mut out: Vec<(usize, BigUint)> = Vec::with_capacity(BUCKET_DOMAIN);

    for pos in 0..BUCKET_DOMAIN {
        let c1 = bd1.enc_by_pos.get(&pos)
            .expect("H1 : ciphertext manquant pour un bucket du domaine dense");
        let c2 = bd2.enc_by_pos.get(&pos)
            .expect("H2 : ciphertext manquant pour un bucket du domaine dense");

        // Soustraction homomorphe Paillier : Enc(m1_p) * Enc(m2_p)^{-1} = Enc(m1_p - m2_p mod N)
        let c2_inv = mod_inverse(c2, n2).expect("mod_inverse(Enc(m2_p)) a echoue");
        let diff   = (c1 * &c2_inv) % n2;

        // r_p ALÉATOIRE et SECRET (jamais transmis, ni à H1 ni à H2) : non nul.
        let one = BigUint::from(1u32);
        let r_p = rng.gen_biguint_range(&one, n);

        // D_p = Enc(m1_p - m2_p)^{r_p} = Enc( r_p * (m1_p - m2_p) mod N )
        let d_p = diff.modpow(&r_p, n2);
        out.push((pos, d_p));
    }

    println!(
        "  [Phase 3] termine en {:.3?} — {} tests d'egalite aveugles envoyes.",
        t_start.elapsed(), out.len()
    );

    out
}

// ---------------------------------------------------------
// Phase 4 (exact-match) — H1 : déchiffrement CIBLÉ.
//
// H1 ne déchiffre que les buckets où SA PROPRE table est active
// (connu localement, sans aide du serveur) : cela exclut le cas
// "les deux vides" (0-0=0 compterait à tort comme match), et
// limite le nombre de déchiffrements à n_H1 (pas BUCKET_DOMAIN).
// ---------------------------------------------------------

pub fn phase4_decrypt_exact_count(
    label:      &str,
    results:    &[(usize, BigUint)],
    own_table:  &BucketTable,
    kp:         &KeyPair,
) -> usize {
    println!(
        "  [Phase 4] {} : verification exacte sur {} bucket(s) actif(s) local(aux)...",
        label, own_table.len()
    );
    let t_start = Instant::now();

    let by_pos: HashMap<usize, &BigUint> = results.iter().map(|(p, d)| (*p, d)).collect();
    let zero = BigUint::from(0u32);

    let mut count = 0usize;
    for &pos in own_table.values.keys() {
        let d_p = by_pos.get(&pos)
            .expect("D_p manquant pour un bucket actif de H1 (reponse serveur incomplete)");
        let m = p_decrypt(d_p, &kp.public_key, &kp.secret_key)
            .expect("p_decrypt(D_p) a echoue");
        if m == zero {
            count += 1;
        }
    }

    println!(
        "  [Phase 4] {} : termine en {:.3?} ({} Dec Paillier, {} correspondance(s) exacte(s))  ->  cardinal = {}",
        label, t_start.elapsed(), own_table.len(), count, count
    );

    count
}
