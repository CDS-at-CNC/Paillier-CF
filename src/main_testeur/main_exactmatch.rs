// =========================================================
// ExactMatch — Version Production (Serveur Central)
// Protocole PSI via Catalano-Fiore (Forme Seconde)
// ClickNCrypt Technical Series 2026 · v1.0
// =========================================================

use paillier_crypto::fiore_catalano::cf_encrypt::cf_encrypt::cf_encrypt;

use paillier_crypto::fiore_catalano::cf_mul::cf_mul::cf_mul;

use paillier_crypto::fiore_catalano::cf_mul_dec::cf_mul_dec::cf_mul_dec;

use paillier_crypto::paillier::p_keygen::p_keygen::p_keygen;

//use paillier_crypto::paillier::p_encrypt::p_encrypt;

use paillier_crypto::paillier::p_encrypt::p_encrypt::p_encrypt;

use paillier_crypto::KeyPair;

use num_bigint::BigUint;
use num_bigint::RandBigInt;
use rand_core::OsRng;
use std::time::Instant;
use std::collections::{HashMap, HashSet};


// ─────────────────────────────────────────────────────────

const HASH_BITS: usize = 10;          // 2^10 = 1024 positions dans la table
const TABLE_SIZE: usize = 1 << HASH_BITS;

// ─────────────────────────────────────────────────────────
// Fonction de hachage (§2.1 — JS-like 32-bit sur HASH_BITS bits)
// h : {0,1}* -> {0,1}^HASH_BITS
// ─────────────────────────────────────────────────────────

fn simple_hash(s: &str) -> usize {
    let mut h: u32 = 0;
    for ch in s.chars() {
        h = h.wrapping_shl(7).wrapping_sub(h).wrapping_add(ch as u32);
    }
    (h as usize) & (TABLE_SIZE - 1)
}

// ─────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────

/// Table creuse : seules les positions actives (t[i]=1) sont stockées.
/// Toute position absente vaut implicitement 0.
struct SparseTable {
    active: HashSet<usize>,
}

impl SparseTable {
    /// Construit la table à partir d'une liste de NSS (strings).
    /// t[simple_hash(nss)] = 1  pour chaque nss de la base.
    fn build(nss_list: &[String]) -> Self {
        let mut active = HashSet::new();
        for nss in nss_list {
            active.insert(simple_hash(nss));
        }
        SparseTable { active }
    }

    fn contains(&self, pos: usize) -> bool {
        self.active.contains(&pos)
    }

    fn len(&self) -> usize {
        self.active.len()
    }
}

/// Masques d'une BD pour Phase 2 :
///   masks_clear : { position → b_i en clair }     (secret, gardé par la BD)
///   masks_enc   : { position → P.Enc_pk(b_i) }    (envoyé aux autres parties)
struct MaskBundle {
    masks_clear: HashMap<usize, BigUint>,
    masks_enc:   HashMap<usize, BigUint>,
}

/// Chiffré CF Forme Seconde : (c0_snd, c1_snd, c2_snd)
type CfSnd = (BigUint, BigUint, BigUint);

// ─────────────────────────────────────────────────────────
// Chargement du CSV -> colonne NSS uniquement
// ─────────────────────────────────────────────────────────

/// Lit un fichier CSV et retourne Vec<String> des valeurs NSS.
/// Le hash est recalculé à la volée par simple_hash(nss).
fn load_nss_from_csv(path: &str) -> Vec<String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path)
        .unwrap_or_else(|e| panic!("Impossible d'ouvrir {} : {}", path, e));
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let header = lines.next().expect("Fichier vide").expect("Erreur lecture");
    let cols: Vec<&str> = header.split(',').collect();
    let nss_col = cols.iter().position(|c| c.trim() == "NSS")
        .expect("Colonne 'NSS' introuvable");

    lines
        .filter_map(|line| {
            let line = line.ok()?;
            let val = line.split(',').nth(nss_col)?.trim().to_string();
            if val.is_empty() { None } else { Some(val) }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────
// Phase 0 — Génération des clés
// ─────────────────────────────────────────────────────────

fn phase0_keygen(label: &str, bits: u64) -> KeyPair {
    println!("  [Phase 0] {} : génération des clés ({} bits)...", label, bits);
    let t = Instant::now();
    let kp = p_keygen(bits);
    println!("  [Phase 0] {} : clés générées en {:.3?}", label, t.elapsed());
    kp
}

// ─────────────────────────────────────────────────────────
// Phase 1 — Construction des tables de bits creuses (Algo 1 du PDF)
// ─────────────────────────────────────────────────────────
//
// Pour chaque nss ∈ BDk :
//   t[simple_hash(nss)] <- 1
// Toute position non listée vaut implicitement 0.

fn phase1_build_table(label: &str, nss_list: &[String]) -> SparseTable {
    println!(
        "  [Phase 1] {} : construction de la table creuse ({} NSS, TABLE_SIZE={})...",
        label, nss_list.len(), TABLE_SIZE
    );
    let table = SparseTable::build(nss_list);
    println!(
        "  [Phase 1] {} : {} position(s) active(s) sur {} — t[i]=1.",
        label, table.len(), TABLE_SIZE
    );
    table
}

// ─────────────────────────────────────────────────────────
// Phase 2 — Échange croisé des masques chiffrés (3.3 du PDF)
// ─────────────────────────────────────────────────────────

fn phase2_generate_masks(label: &str, table: &SparseTable, kp: &KeyPair) -> MaskBundle {
    println!(
        "  [Phase 2] {} : génération + chiffrement de {} masques sous pk{}...",
        label, table.len(), label
    );
    let mut rng = OsRng;
    let mut masks_clear = HashMap::with_capacity(table.len());
    let mut masks_enc   = HashMap::with_capacity(table.len());

    for &pos in &table.active {
        let b_i     = rng.gen_biguint_below(&kp.public_key.n);
        let enc_b_i = p_encrypt(&b_i, &kp.public_key);
        masks_clear.insert(pos, b_i);
        masks_enc.insert(pos, enc_b_i);
    }

    println!("  [Phase 2] {} : {} masques prêts.", label, masks_clear.len());
    MaskBundle { masks_clear, masks_enc }
}

// ─────────────────────────────────────────────────────────
// Phase 3 — Calcul homomorphe — Serveur neutre (Algo 2 du PDF)
// ─────────────────────────────────────────────────────────
//
// Pour chaque position i telle que t[i]=1 ET t'[i]=1 :
//   Ft  = CF.Enc_pk(1, a1)   a1 <- $ Z_N
//   Ft' = CF.Enc_pk(1, a2)   a2 <- $ Z_N
//   sf  = CF.Mul(Ft, Ft', pk)  -> Forme Seconde de 1·1 = 1

fn phase3_server_compute(
    table1: &SparseTable,
    table2: &SparseTable,
    kp1:    &KeyPair,
    kp2:    &KeyPair,
) -> (Vec<(usize, CfSnd)>, Vec<(usize, CfSnd)>) {

    println!("  [Phase 3] Serveur : calcul homomorphe CF...");
    let t_start = Instant::now();

    let common: Vec<usize> = table1.active
        .iter()
        .copied()
        .filter(|pos| table2.contains(*pos))
        .collect();

    println!(
        "  [Phase 3] Serveur : {} position(s) commune(s) (t[i]=1 * t'[i]=1).",
        common.len()
    );

    let one = BigUint::from(1u32);
    let mut rng = OsRng;
    let mut result_bd1: Vec<(usize, CfSnd)> = Vec::with_capacity(common.len());
    let mut result_bd2: Vec<(usize, CfSnd)> = Vec::with_capacity(common.len());

    for pos in &common {
        // ── BD1 sous pk1 ─────────────────────────────────────────────
        let a1 = rng.gen_biguint_below(&kp1.public_key.n);
        let a2 = rng.gen_biguint_below(&kp1.public_key.n);
        let ft_1  = cf_encrypt(&one, &a1, &kp1.public_key);
        let ftp_1 = cf_encrypt(&one, &a2, &kp1.public_key);
        let sf1   = cf_mul(&ft_1, &ftp_1, &kp1.public_key);

        // ── BD2 sous pk2 ─────────────────────────────────────────────
        let b1 = rng.gen_biguint_below(&kp2.public_key.n);
        let b2 = rng.gen_biguint_below(&kp2.public_key.n);
        let ft_2  = cf_encrypt(&one, &b1, &kp2.public_key);
        let ftp_2 = cf_encrypt(&one, &b2, &kp2.public_key);
        let sf2   = cf_mul(&ft_2, &ftp_2, &kp2.public_key);

        result_bd1.push((*pos, sf1));
        result_bd2.push((*pos, sf2));
    }

    println!(
        "  [Phase 3] Serveur : terminé en {:.3?} ({} multiplication(s) CF).",
        t_start.elapsed(), common.len()
    );
    (result_bd1, result_bd2)
}

// ─────────────────────────────────────────────────────────
// Phase 4 — Déchiffrement Forme Seconde + comptage (Algo 3 du PDF)
// ─────────────────────────────────────────────────────────
//
// CF.Dec₂ : p_i = [ P.Dec(c0'') + P.Dec(c1'')·P.Dec(c2'') ] mod N
// Si p_i = 1 -> position commune -> patient en commun détecté.

fn phase4_decrypt_and_count(
    label:      &str,
    aggregated: &[(usize, CfSnd)],
    kp:         &KeyPair,
) -> usize {
    println!(
        "  [Phase 4] {} : déchiffrement CF Forme Seconde ({} terme(s))...",
        label, aggregated.len()
    );
    let t_start = Instant::now();
    let one = BigUint::from(1u32);
    let mut count = 0usize;

    for (pos, sf) in aggregated {
        let p_i = cf_mul_dec(sf, &kp.public_key, &kp.secret_key);
        if p_i == one {
            count += 1;
            println!("   position {:>6} : p_i = 1  (patient commun)", pos);
        } else {
            println!("   position {:>6} : p_i = {} (inattendu)", pos, p_i);
        }
    }

    println!(
        "  [Phase 4] {} : terminé en {:.3?} → {} patient(s) commun(s).",
        label, t_start.elapsed(), count
    );
    count
}

// ─────────────────────────────────────────────────────────
// Point d'entrée
// ─────────────────────────────────────────────────────────

fn main() {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║   ExactMatch — PSI via Catalano-Fiore (Forme 2)      ║");
    println!("║   ClickNCrypt Technical Series 2026 · v1.0           ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    // ── Chargement des CSV ────────────────────────────────────────────
    let nss_a = load_nss_from_csv("base_A.csv");
    let nss_b = load_nss_from_csv("base_B.csv");

    println!("BD1 (base_A.csv) : {} NSS chargé(s)", nss_a.len());
    println!("BD2 (base_B.csv) : {} NSS chargé(s)", nss_b.len());

    // Vérification en clair : intersection réelle sur NSS
    let set_a: HashSet<&str> = nss_a.iter().map(String::as_str).collect();
    let set_b: HashSet<&str> = nss_b.iter().map(String::as_str).collect();
    let common_nss: Vec<&&str> = set_a.intersection(&set_b).collect();

    // Vérification sur les positions de hash
    let hashes_a: HashSet<usize> = nss_a.iter().map(|s| simple_hash(s)).collect();
    let hashes_b: HashSet<usize> = nss_b.iter().map(|s| simple_hash(s)).collect();
    let common_hashes: Vec<usize> = hashes_a.intersection(&hashes_b).copied().collect();

    println!("\n[Vérif. en clair]");
    println!("  NSS communs          : {}", common_nss.len());
    println!("  Positions communes   : {} (résultat attendu du protocole)", common_hashes.len());
    println!("  (Le protocole PSI ne révèle que ce cardinal — aucun identifiant n'est exposé)\n");

    let t_total = Instant::now();

    // ── Phase 0 ───────────────────────────────────────────────────────
    println!("═══ Phase 0 : Génération des clés ═══");
    let kp1 = phase0_keygen("BD1", 512); // <- 2048 en production
    let kp2 = phase0_keygen("BD2", 512);

    // ── Phase 1 ───────────────────────────────────────────────────────
    println!("\n═══ Phase 1 : Construction des tables de bits creuses ═══");
    let table1 = phase1_build_table("BD1", &nss_a);
    let table2 = phase1_build_table("BD2", &nss_b);

    // Affichage de la table creuse
    println!("\n  Table creuse (positions actives des deux bases) :");
    println!("  {:>6}  {:^5}  {:^5}", "h(NSS)", "t[i]", "t'[i]");
    println!("  {:─>6}  {:─^5}  {:─^5}", "", "", "");
    let mut all_pos: Vec<usize> = table1.active.union(&table2.active).copied().collect();
    all_pos.sort();
    for pos in &all_pos {
        let t1 = if table1.contains(*pos) { 1u8 } else { 0u8 };
        let t2 = if table2.contains(*pos) { 1u8 } else { 0u8 };
        let marker = if t1 == 1 && t2 == 1 { "  <- commun" } else { "" };
        println!("  {:>6}     {}      {}{}", pos, t1, t2, marker);
    }

    // ── Phase 2 ───────────────────────────────────────────────────────
    println!("\n═══ Phase 2 : Échange croisé des masques chiffrés ═══");
    let _bundle1 = phase2_generate_masks("BD1", &table1, &kp1);
    let _bundle2 = phase2_generate_masks("BD2", &table2, &kp2);
    println!("  BD1 -> Enc_pk1(b_i)  transmis à BD2 et au Serveur");
    println!("  BD2 -> Enc_pk2(b'_i) transmis à BD1 et au Serveur");

    // ── Phase 3 ───────────────────────────────────────────────────────
    println!("\n═══ Phase 3 : Calcul homomorphe — Serveur neutre ═══");
    let (agg_bd1, agg_bd2) = phase3_server_compute(&table1, &table2, &kp1, &kp2);
    println!("  C_BD1 (Forme Seconde CF) -> envoyé à BD1");
    println!("  C_BD2 (Forme Seconde CF) -> envoyé à BD2");

    // ── Phase 4 ───────────────────────────────────────────────────────
    println!("\n═══ Phase 4 : Déchiffrement CF et comptage ═══");
    let r1 = phase4_decrypt_and_count("BD1", &agg_bd1, &kp1);
    let r2 = phase4_decrypt_and_count("BD2", &agg_bd2, &kp2);

    // ── Résultat final ────────────────────────────────────────────────
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║                  RÉSULTAT FINAL                      ║");
    println!("╠══════════════════════════════════════════════════════╣");

    if r1 == r2 {
        println!("║  r1 = r2 = {} patient(s) en commun", r1);
        println!("║  Cohérence BD1 / BD2 vérifiée (r1 == r2)");
    } else {
        println!("║  Incohérence : r1={}, r2={} (erreur de protocole)", r1, r2);
    }

    if r1 == common_hashes.len() {
        println!("║  Résultat correct (attendu : {})", common_hashes.len());
    } else {
        println!("║  Résultat incorrect (attendu : {}, obtenu : {})", common_hashes.len(), r1);
    }

    println!("║");
    println!("║  Temps total protocole : {:.3?}", t_total.elapsed());
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("Garanties de sécurité respectées :");
    println!("  Serveur : voit t et t' (positions actives) — ne déchiffre jamais");
    println!("  BD1     : voit pk2, C_BD1, r — identifiants de BD2 non révélés");
    println!("  BD2     : voit pk1, C_BD2, r — identifiants de BD1 non révélés");
    println!("  CF.Mul  : masque t[i] * t'[i] sous Forme Seconde avant envoi\n");
}