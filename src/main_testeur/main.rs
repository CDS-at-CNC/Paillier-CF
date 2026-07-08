// =========================================================
// main.rs — ExactMatch PSI Catalano-Fiore
// ClickNCrypt Technical Series 2026 · v1.0
// =========================================================

use paillier_crypto::exactmatch::{
    load_nss_from_csv,
    simple_hash,
    phase0_keygen,
    phase1_build_table,
    phase2_prepare_dual_ft,
    phase3_server_compute,
    phase4_decrypt_and_count,
};
use std::collections::HashSet;
use std::time::Instant;

fn main() {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║   ExactMatch — PSI via Catalano-Fiore (Forme 2)      ║");
    println!("║   ClickNCrypt Technical Series 2026 · v1.0           ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    // ── Chargement des CSV ────────────────────────────────────────────
    let nss_a = load_nss_from_csv("base_A_1000_600.csv");
    let nss_b = load_nss_from_csv("base_B_1000_600.csv");

    println!("BD1 (base_A.csv) : {} NSS charge(s)", nss_a.len());
    println!("BD2 (base_B.csv) : {} NSS charge(s)", nss_b.len());

    // Reference en clair : intersection sur les positions de hash
    let hashes_a: HashSet<usize> = nss_a.iter().map(|s| simple_hash(s)).collect();
    let hashes_b: HashSet<usize> = nss_b.iter().map(|s| simple_hash(s)).collect();
    let common_hashes: Vec<usize> = hashes_a.intersection(&hashes_b).copied().collect();

    println!("  Positions communes   : {} (resultat attendu du protocole)", common_hashes.len());
    println!("  (Le protocole PSI ne revele que ce cardinal)\n");

    let t_total = Instant::now();

    // ── Phase 0 — Generation des cles ─────────────────────────────────
    println!("=== Phase 0 : Generation des cles ===");
    let kp1 = phase0_keygen("BD1", 128);   // 2048 bits en production
    let kp2 = phase0_keygen("BD2", 128);

    // ── Phase 1 — Construction des tables creuses ─────────────────────
    println!("\n=== Phase 1 : Construction des tables creuses ===");
    let table1 = phase1_build_table("BD1", &nss_a);
    let table2 = phase1_build_table("BD2", &nss_b);

    // ── Phase 2 — Echange croise des masques chiffres ─────────────────
    //
    // CORRECTION : phase2_prepare_dual_ft prend maintenant 4 arguments :
    //   (label, table, kp1, kp2)
    //
    // AVANT (faux) :
    //   let bundle1 = phase2_prepare_dual_ft("BD1", &table1, &kp1);   <- 3 args
    //   let bundle2 = phase2_prepare_dual_ft("BD2", &table2, &kp2);   <- 3 args
    //
    // APRES (correct) :
    //   Les deux BD passent kp1 ET kp2 pour produire des Ft dans
    //   Z_{n1} et Z_{n2} (necessaire car n1 != n2).
    println!("\n=== Phase 2 : Echange croise des masques chiffres ===");
    let bundle1 = phase2_prepare_dual_ft("BD1", &table1, &kp1, &kp2);
    let bundle2 = phase2_prepare_dual_ft("BD2", &table2, &kp1, &kp2);
    println!("  BD1 -> Ft(pk1), Ft(pk2)  transmis au Serveur");
    println!("  BD2 -> Ft(pk1), Ft(pk2)  transmis au Serveur");

    // ── Phase 3 — Calcul homomorphe (Serveur neutre) ──────────────────
    println!("\n=== Phase 3 : Calcul homomorphe — Serveur neutre ===");
    let (agg_bd1, agg_bd2) = phase3_server_compute(
        &table1, &table2,
        &bundle1, &bundle2,
        &kp1, &kp2,
    );
    println!("  C_BD1 (triplets CF.Mul sous pk1) -> envoye a BD1");
    println!("  C_BD2 (triplets CF.Mul sous pk2) -> envoye a BD2");

    // ── Phase 4 — Dechiffrement + comptage ────────────────────────────
    println!("\n=== Phase 4 : Dechiffrement CF et comptage ===");
    let r1 = phase4_decrypt_and_count("BD1", &agg_bd1, &kp1);
    let r2 = phase4_decrypt_and_count("BD2", &agg_bd2, &kp2);

    // ── Resultat final ────────────────────────────────────────────────
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║                  RESULTAT FINAL                      ║");
    println!("╠══════════════════════════════════════════════════════╣");

    if r1 == r2 {
        println!("║  r1 = r2 = {}  patient(s) en commun", r1);
        println!("║  Coherence BD1 / BD2 verifiee (r1 == r2)");
    } else {
        println!("║  Incoherence : r1={}, r2={} (erreur de protocole)", r1, r2);
    }

    if r1 == common_hashes.len() {
        println!("║  Resultat correct  (attendu : {})", common_hashes.len());
    } else {
        println!("║  Resultat incorrect  (attendu : {}, obtenu : {})", common_hashes.len(), r1);
    }

    println!("║");
    println!("║  Temps total protocole : {:.3?}", t_total.elapsed());
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("Garanties de securite respectees :");
    println!("  Serveur : voit t et t' (positions actives) + Ft chiffres");
    println!("            calcule CF.Mul et agregee — ne dechiffre jamais");
    println!("  BD1     : recoit triplets sous pk1 — voit uniquement r = |BD1 ^ BD2|");
    println!("  BD2     : recoit triplets sous pk2 — voit uniquement r = |BD1 ^ BD2|");
}
