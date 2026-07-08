// =========================================================
// Métriques — Mesures de durée des cryptosystèmes
// Paillier & Catalano-Fiore (avec choix interactif)
// =========================================================

// ── Paillier ──────────────────────────────────────────────
use paillier_crypto::paillier::p_keygen::p_keygen::p_keygen;
use paillier_crypto::paillier::p_encrypt::p_encrypt::p_encrypt;
use paillier_crypto::paillier::p_decrypt::p_decrypt::p_decrypt;

// ── multiplication Rapide de karatsuba (utilisé dans les deux cryptosystèmes) ──────────────────────────────
use paillier_crypto::karatsuba_mul::karatsuba_mul::fast_mul;
// ── Catalano-Fiore ────────────────────────────────────────
use paillier_crypto::fiore_catalano::cf_encrypt::cf_encrypt::cf_encrypt;
use paillier_crypto::fiore_catalano::cf_add::cf_add::cf_add;
use paillier_crypto::fiore_catalano::cf_add::cf_add_dec::cf_add_dec;
use paillier_crypto::fiore_catalano::cf_mul::cf_mul::cf_mul;
use paillier_crypto::fiore_catalano::cf_mul_dec::cf_mul_dec::cf_mul_dec;

// ── Gestion des clés ──────────────────────────────────────
use paillier_crypto::key_management::{
    key_file_exists, ensure_keys_directory,
    save_keypair_json, save_public_key_json, save_secret_key_json,
    load_keypair_json,
};

// ── Types et erreurs ──────────────────────────────────────
use paillier_crypto::CryptoError;
use paillier_crypto::KeyPair;

// ── Stdlib & crates externes ──────────────────────────────

use rand::Rng;
use rand_core::OsRng;
use num_bigint::{BigUint, RandBigInt};
use std::io::{self, Write};
use std::time::Instant;

// ── Chemins des fichiers de clés ──────────────────────────
const KEYS_DIR:             &str = "keys";
const KEYPAIR_JSON_PATH:    &str = "keys/keypair.json";
const PUBLIC_KEY_JSON_PATH: &str = "keys/public_key.json";
const SECRET_KEY_JSON_PATH: &str = "keys/secret_key.json";

// ─────────────────────────────────────────────────────────
// Erreur applicative centrale
//
// Unifie CryptoError et io::Error pour propager toutes les
// erreurs via ? sans conversion manuelle — plus aucun panic!
// ─────────────────────────────────────────────────────────

#[derive(Debug)]
enum AppError {
    Crypto(CryptoError),
    Io(std::io::Error),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Crypto(e) => write!(f, "Erreur cryptographique : {}", e),
            AppError::Io(e)     => write!(f, "Erreur I/O : {}", e),
        }
    }
}

impl From<CryptoError> for AppError {
    fn from(e: CryptoError) -> Self { AppError::Crypto(e) }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self { AppError::Io(e) }
}

// ─────────────────────────────────────────────────────────
// Point d'entrée
// ─────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = ensure_keys_directory(KEYS_DIR) {
        eprintln!("[FATAL] Impossible de créer le répertoire keys/ : {}", e);
        std::process::exit(1);
    }

    loop {
        afficher_menu();
        let choix = lire_choix();

        let res = match choix.as_str() {
            "1" => demonstration_paillier(),
            "2" => demonstration_catalano_fiore(),
            "3" => { println!("\nAu revoir !\n"); break; }
            _   => { println!("\nChoix invalide. Veuillez choisir 1, 2 ou 3.\n"); continue; }
        };

        if let Err(e) = res {
            eprintln!("\n[ERREUR] {}\n", e);
        }

        println!("\nAppuyez sur Entrée pour continuer...");
        let mut pause = String::new();
        io::stdin().read_line(&mut pause).ok();
    }
}

// ─────────────────────────────────────────────────────────
// Menu
// ─────────────────────────────────────────────────────────

fn afficher_menu() {
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║   MÉTRIQUES CRYPTOSYSTÈMES — MENU             ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!("\n  [1] Cryptosystème de Paillier");
    println!("  [2] Cryptosystème de Catalano-Fiore");
    println!("  [3] Quitter\n");
    print!("Votre choix : ");
    io::stdout().flush().ok();
}

fn lire_choix() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim().to_string()
}

// ─────────────────────────────────────────────────────────
// Gestion des clés : chargement ou génération + sauvegarde
// ─────────────────────────────────────────────────────────

fn charger_ou_generer_cles(bits: u64) -> Result<(KeyPair, Option<std::time::Duration>), AppError> {
    if key_file_exists(KEYPAIR_JSON_PATH) {
        println!("\n  Clés existantes détectées — chargement...");
        let t = Instant::now();
        match load_keypair_json(KEYPAIR_JSON_PATH) {
            Ok(kp) => {
                println!("  Clés chargées depuis le disque ({:.3?})\n", t.elapsed());
                return Ok((kp, None));
            }
            Err(e) => println!("  Erreur de chargement ({}) — regénération...", e),
        }
    } else {
        println!("\n  Aucune clé trouvée — génération ({} bits)...", bits);
    }
    let (kp, d) = generer_et_sauvegarder(bits)?;
    Ok((kp, Some(d)))
}

fn generer_et_sauvegarder(bits: u64) -> Result<(KeyPair, std::time::Duration), AppError> {
    let t       = Instant::now();
    let keypair = p_keygen(bits)?;          // Result<KeyPair, CryptoError> — propagé via ?
    let duree   = t.elapsed();
    println!("  Clés générées ({} bits) — temps : {:.3?}\n", bits, duree);

    save_keypair_json(&keypair, KEYPAIR_JSON_PATH)?;
    save_public_key_json(&keypair.public_key, PUBLIC_KEY_JSON_PATH)?;
    save_secret_key_json(&keypair.secret_key, SECRET_KEY_JSON_PATH)?;
    println!("  Clés sauvegardées dans {}/\n", KEYS_DIR);

    Ok((keypair, duree))
}

fn afficher_cles(kp: &KeyPair) {
    println!("--- CLÉ PUBLIQUE ---");
    println!("  |n|         = {} bits", kp.public_key.n.bits());
    println!("  g           = {}", kp.public_key.g);
    println!("  |n_squared| = {} bits", kp.public_key.n_squared.bits());
    println!("--- CLÉ SECRÈTE ---");
    println!("  |lambda|    = {} bits", kp.secret_key.lambda.bits());
    println!("  |mu|        = {} bits", kp.secret_key.mu.bits());
}

// ─────────────────────────────────────────────────────────
// [1] Démonstration Paillier — homomorphisme additif
// ─────────────────────────────────────────────────────────

fn demonstration_paillier() -> Result<(), AppError> {
    println!("\n==============================================");
    println!("    Cryptosystème de Paillier — Démonstration");
    println!("==============================================");

    let (kp, duree_keygen) = charger_ou_generer_cles(1536)?;
    afficher_cles(&kp);

    // Messages dans [0, n) — domaine valide Paillier
    let mut rng      = OsRng;
    let m1           = rng.gen_biguint_below(&kp.public_key.n);
    let m2           = rng.gen_biguint_below(&kp.public_key.n);
    let somme_claire = (&m1 + &m2) % &kp.public_key.n;

    println!("\n  m1            = {} bits", m1.bits());
    println!("  m2            = {} bits", m2.bits());
    println!("  (m1+m2) mod n = {} bits", somme_claire.bits());

    // p_encrypt retourne Result<BigUint, CryptoError>
    let t            = Instant::now();
    let c1           = p_encrypt(&m1, &kp.public_key)?;
    let duree_enc_m1 = t.elapsed();

    let t            = Instant::now();
    let c2           = p_encrypt(&m2, &kp.public_key)?;
    let duree_enc_m2 = t.elapsed();

    // Addition homomorphique : E(m1) * E(m2) mod n² = E((m1+m2) mod n)
    let t            = Instant::now();
    let c_somme      = (&c1 * &c2) % &kp.public_key.n_squared;
    let duree_add    = t.elapsed();

    // p_decrypt retourne Result<BigUint, CryptoError>
    let t            = Instant::now();
    let dec          = p_decrypt(&c_somme, &kp.public_key, &kp.secret_key)?;
    let duree_dec    = t.elapsed();

    if dec == somme_claire {
        println!("\n Homomorphisme additif vérifié : D(E(m1)·E(m2)) = (m1+m2) mod n");
    } else {
        println!("\n Erreur dans l'homomorphisme additif !");
    }

    println!("\n==============================================");
    println!("    RÉSUMÉ DES TEMPS — Paillier");
    println!("==============================================");
    match duree_keygen {
        Some(d) => println!("  Génération des clés    : {:.3?}  (nouvelle génération)", d),
        None    => println!("  Génération des clés    : —  (chargées depuis le disque)"),
    }
    println!("  Chiffrement m1         : {:.3?}", duree_enc_m1);
    println!("  Chiffrement m2         : {:.3?}", duree_enc_m2);
    println!("  Addition homomorphique : {:.3?}", duree_add);
    println!("  Déchiffrement          : {:.3?}", duree_dec);
    println!("==============================================");

    Ok(())
}

// ─────────────────────────────────────────────────────────
// [2] Démonstration Catalano-Fiore — addition et multiplication
// ─────────────────────────────────────────────────────────

fn demonstration_catalano_fiore() -> Result<(), AppError> {
    println!("\n==============================================");
    println!("  Cryptosystème Catalano-Fiore — Démonstration");
    println!("==============================================");

    let (kp, _duree_keygen) = charger_ou_generer_cles(1536)?;
    afficher_cles(&kp);

    let mut rng = OsRng;

	let m1 = rng.gen_biguint(3071);
	let m2 = rng.gen_biguint(3071);
    //let m1 = rng.gen_biguint_below(&kp.public_key.n);
    //let m2 = rng.gen_biguint_below(&kp.public_key.n);

    let b1 = rng.gen_biguint_below(&kp.public_key.n); // masque aléatoire de m1
    let b2 = rng.gen_biguint_below(&kp.public_key.n); // masque aléatoire de m2
  

	//let b2 = rng.gen_biguint(5);



    //println!("\n  m1 = {} bits", m1.bits());
    //println!("  m2 = {} bits", m2.bits());

    // cf_encrypt retourne Result<(BigUint, BigUint), CryptoError>
    let t             = Instant::now();
    let cf1           = cf_encrypt(&m1, &b1, &kp.public_key)?;
    let duree_enc_cf1 = t.elapsed();

    let t             = Instant::now();
    let cf2           = cf_encrypt(&m2, &b2, &kp.public_key)?;
    let duree_enc_cf2 = t.elapsed();

    println!("\n  Chiffrement CF m1 : {:.3?}", duree_enc_cf1);
    println!("  Chiffrement CF m2 : {:.3?}", duree_enc_cf2);

    // ── FORME 1 — Addition homomorphique CF ───────────────────────────
    println!("\n==================================");
    println!("  FORME 1 — Addition homomorphique");
    println!("==================================");

    // cf_add retourne désormais Result<(BigUint, BigUint), CryptoError>
    let t            = Instant::now();
    let forme1       = cf_add(&cf1, &cf2, &kp.public_key.n, &kp.public_key.n_squared)?;
    let duree_add    = t.elapsed();
    println!("  Addition CF               : {:.3?}", duree_add);

    // cf_add_dec retourne Result<BigUint, CryptoError>
    let t            = Instant::now();
    let dec_add      = cf_add_dec(&forme1, &kp.public_key, &kp.secret_key)?;
    let duree_add_dec = t.elapsed();
    println!("  Déchiffrement addition CF : {:.3?}", duree_add_dec);

    let somme_attendue = (&m1 + &m2) % &kp.public_key.n;
    if dec_add == somme_attendue {
        println!("  Addition CF vérifiée : D(CF.Add(E(m1), E(m2))) = m1+m2");
    } else {
        println!("  Erreur dans l'addition CF !");
    }

    // ── FORME 2 — Multiplication homomorphique CF ─────────────────────
    println!("\n==================================");
    println!("  FORME 2 — Multiplication homomorphique");
    println!("==================================");

    // cf_mul retourne Result<(BigUint, BigUint, BigUint), CryptoError>
    let t            = Instant::now();
    let forme2       = cf_mul(&cf1, &cf2, &kp.public_key)?;
    let duree_mul    = t.elapsed();

    //println!("Le produit des deux messages est : {:?}", forme2);
    println!("  Multiplication CF         : {:.3?}", duree_mul);

    // cf_mul_dec retourne Result<BigUint, CryptoError>
    let t            = Instant::now();
    let dec_mul      = cf_mul_dec(&forme2, &kp.public_key, &kp.secret_key)?;
    let duree_mul_dec = t.elapsed();
    println!("Le produit des deux message est {:?}", dec_mul);
    println!("  Déchiffrement produit CF  : {:.3?}", duree_mul_dec);

    let t = Instant::now();
    let produit_attendu = (&m1 * &m2) % &kp.public_key.n;
    let duree_verif = t.elapsed();

    if dec_mul == produit_attendu {
        println!("  Multiplication CF vérifiée : D(CF.Mul(E(m1), E(m2))) = m1*m2");
    } else {
        println!("  Erreur dans la multiplication CF !");
    }

    println!("\n==============================================");
    println!("    RÉSUMÉ DES TEMPS — Catalano-Fiore");
    println!("==============================================");
   /*  match duree_keygen {
        Some(d) => println!("  Génération des clés           : {:.3?}  (nouvelle génération)", d),
        None    => println!("  Génération des clés           : —  (chargées depuis le disque)"),
    }
 */
    println!("Le produit initial est {:?}", (&m1*&m2) % &kp.public_key.n);
    println!("  La durée du produit en clair es : {:.3?}", duree_verif);
    println!("  Chiffrement CF m1             : {:.3?}", duree_enc_cf1);
    println!("  Chiffrement CF m2             : {:.3?}", duree_enc_cf2);
    println!("  Addition homomorphique CF     : {:.3?}", duree_add);
    println!("  Déchiffrement addition CF     : {:.3?}", duree_add_dec);
    println!("  Multiplication homomorphique  : {:.3?}", duree_mul);
    println!("  Déchiffrement multiplication  : {:.3?}", duree_mul_dec);
    println!("==============================================");


    let t = Instant::now();
    let produit = fast_mul(&m1, &m2, &kp.public_key.n)?;
    let duree_mul_clair = t.elapsed();
    println!("Le produit de m1 et m2 est : {:?}, la durée {:?}", produit, duree_mul_clair);
    println!("La duréee de la multiplication en clair est : {:.3?}", duree_mul);



    Ok(())
}