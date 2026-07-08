use paillier_crypto::key_management::key_storage;

// POUR LE CALCUL

use rand_core::OsRng;
use std::io::{self, Write};
use std::time::Instant;
use num_bigint::RandBigInt;

//POUR PAILLIER

use paillier_crypto::KeyPair;
use paillier_crypto::p_keygen::p_keygen;
use paillier_crypto::p_encrypt::p_encrypt::p_encrypt;
use paillier_crypto::p_decrypt::p_decrypt::p_decrypt;
use num_bigint::BigUint;


//POUR PAILLIER-KEA

use paillier_crypto::paillier_kea::paillier_kea_keypen;
use paillier_crypto::paillier_kea::paillier_kea_encrypt;
use paillier_crypto::paillier_kea::paillier_kea_img_verif;

//POUR CATALANO-FIORE

use paillier_crypto::fiore_catalano::cf_encrypt::cf_encrypt::cf_encrypt;
use paillier_crypto::fiore_catalano::cf_add::cf_add::cf_add;
use paillier_crypto::fiore_catalano::cf_add::cf_add_dec::cf_add_dec;
use paillier_crypto::fiore_catalano::cf_mul::cf_mul::cf_mul;
use paillier_crypto::fiore_catalano::cf_mul_dec::cf_mul_dec::cf_mul_dec;

use key_storage::*;

// Chemins des fichiers de clés (constants globaux)

const KEYS_DIR:            &str = "keys";
const KEYPAIR_JSON_PATH:   &str = "keys/keypair.json";
const PUBLIC_KEY_JSON_PATH:&str = "keys/public_key.json";
const SECRET_KEY_JSON_PATH:&str = "keys/secret_key.json";
const PUBLIC_KEY_PEM_PATH: &str = "keys/public_key.pem";
const SECRET_KEY_PEM_PATH: &str = "keys/secret_key.pem";


// =====================================================================
//  POINT D'ENTRÉE
// =====================================================================

fn main() {
    // Créer le répertoire des clés une seule fois au démarrage
    ensure_keys_directory(KEYS_DIR)
        .expect("Impossible de créer le répertoire keys/");

    loop {
        afficher_menu_principal();

        let choix = lire_choix();

        match choix.as_str() {
            "1" => demonstration_paillier(),
            "2" => demonstration_fiore_catalano(),
            "3" => {
                println!("\nAu revoir !\n");
                break;
            }
            _ => println!("\nChoix invalide. Veuillez choisir 1, 2 ou 3.\n"),
        }

        println!("\nAppuyez sur Entrée pour continuer...");
        let mut pause = String::new();
        io::stdin().read_line(&mut pause).unwrap();
    }
}


// =====================================================================
//  MENU
// =====================================================================

fn afficher_menu_principal() {
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║   CRYPTOSYSTÈMES HOMOMORPHIQUES - MENU        ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!("\nChoisissez un cryptosystème à démontrer :\n");
    println!("  [1] Cryptosystème de Paillier");
    println!("  [2] Cryptosystème de Fiore-Catalano");
    println!("  [3] Quitter\n");
    print!("Votre choix : ");
    io::stdout().flush().unwrap();
}

fn lire_choix() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}


// =====================================================================
//  GESTION DES CLÉS : chargement ou génération + sauvegarde
// =====================================================================

/// Charge les clés depuis le disque si elles existent,
/// sinon les génère, les sauvegarde et retourne le chrono de génération.
fn charger_ou_generer_cles(bits: usize) -> (KeyPair, Option<std::time::Duration>) {
    if key_file_exists(KEYPAIR_JSON_PATH) {
        println!("\n Clés existantes détectées — chargement...");
        let t = Instant::now();
        match load_keypair_json(KEYPAIR_JSON_PATH) {
            Ok(kp) => {
                let duree = t.elapsed();
                println!(" Clés chargées depuis le disque  ({:.3?})\n", duree);
                (kp, None)          // None = pas de génération, pas de chrono keygen
            }
            Err(e) => {
                println!("  Erreur de chargement ({}) — regénération...", e);
                let (kp, d) = generer_et_sauvegarder(bits);
                (kp, Some(d))
            }
        }
    } else {
        println!("\n Aucune clé trouvée — génération ({} bits)...", bits);
        let (kp, d) = generer_et_sauvegarder(bits);
        (kp, Some(d))
    }
}

/// Génère une nouvelle paire de clés, la sauvegarde dans tous les formats
/// et retourne la paire + la durée de génération.
fn generer_et_sauvegarder(bits: usize) -> (KeyPair, std::time::Duration) {
    let t = Instant::now();

// C'EST ICI QU'ON CHANGE POUR OBTENIR UN MODULE DE TAILLE VOULU : N = p*q
    let keypair: KeyPair = p_keygen(1024);
    let duree = t.elapsed();
    println!(" Clés générées ({} bits) — temps : {:.3?}\n", bits, duree);

    println!(" Sauvegarde des clés...");

    save_keypair_json(&keypair, KEYPAIR_JSON_PATH)
        .expect("Échec sauvegarde keypair.json");
    save_public_key_json(&keypair.public_key, PUBLIC_KEY_JSON_PATH)
        .expect("Échec sauvegarde public_key.json");
    save_secret_key_json(&keypair.secret_key, SECRET_KEY_JSON_PATH)
        .expect("Échec sauvegarde secret_key.json");
    //save_keypair_pem(&keypair, PUBLIC_KEY_PEM_PATH, SECRET_KEY_PEM_PATH).expect("Échec sauvegarde PEM");

    println!(" Clés sauvegardées dans keys/\n");
    afficher_fichiers_cles();

    (keypair, duree)
}

/// Affiche la liste des fichiers de clés créés
fn afficher_fichiers_cles() {
    println!(" Fichiers générés dans «{}»", KEYS_DIR);
    println!("    {} — paire complète (JSON)",  KEYPAIR_JSON_PATH);
    println!("    {} — clé publique (JSON)",    PUBLIC_KEY_JSON_PATH);
    println!("    {} — clé secrète (JSON)",     SECRET_KEY_JSON_PATH);
    println!("    {} — clé publique (PEM)",     PUBLIC_KEY_PEM_PATH);
    println!("    {} — clé secrète (PEM)\n",    SECRET_KEY_PEM_PATH);
}

/// Affiche les composantes des clés
fn afficher_cles(keypair: &KeyPair) {
    println!("--- CLÉ PUBLIQUE ---");
    println!("n    = {}", keypair.public_key.n.bits());
    println!("g    = {}", keypair.public_key.g);
    println!("n^2   = {}", keypair.public_key.n_squared);
    println!("\n--- CLÉ SECRÈTE ---");
    println!("Lambda = {}", keypair.secret_key.lambda);
    println!("mu     = {}", keypair.secret_key.mu);
}


// =====================================================================
//  DÉMONSTRATION PAILLIER
// =====================================================================

fn demonstration_paillier() {
    println!("\n==============================================");
    println!("    Cryptosystème de Paillier - Démonstration");
    println!("==============================================");

    // --- Clés -----------------------------------------------------------
    let (keypair, duree_keygen) = charger_ou_generer_cles(1024);
    afficher_cles(&keypair);

    // --- Messages aléatoires --------------------------------------------
    let mut rng = OsRng;
    let m1 = rng.gen_biguint(1023);
    let m2 = rng.gen_biguint(1023);

    println!("\n==============================================");
    println!("    Démonstration de l'homomorphisme additif");
    println!("==============================================");
    println!("m1       = {}", m1);
    println!("m2       = {}", m2);
    println!("m1 + m2  = {}", &m1 + &m2);

    // --- Chiffrement m1 -------------------------------------------------
    let t = Instant::now();
    let c1 = p_encrypt(&m1, &keypair.public_key);
    let duree_enc_m1 = t.elapsed();
    println!("\n Chiffrement m1 : {:.3?}", duree_enc_m1);
    println!("c1 = {}", c1);

    // --- Chiffrement m2 -------------------------------------------------
    let t = Instant::now();
    let c2 = p_encrypt(&m2, &keypair.public_key);
    let duree_enc_m2 = t.elapsed();
    println!("\n Chiffrement m2 : {:.3?}", duree_enc_m2);
    println!("c2 = {}", c2);

    // --- Addition homomorphique : E(m1) * E(m2) mod n^2 = E(m1+m2) ------
    let t = Instant::now();
    let c_somme = (&c1 * &c2) % &keypair.public_key.n_squared;
    let duree_add_homo = t.elapsed();
    println!("\n Addition homomorphique (c1·c2 mod n^2) : {:.3?}", duree_add_homo);
    println!("c1·c2 mod n^2 = {}", c_somme);

    // --- Déchiffrement --------------------------------------------------
    let t = Instant::now();
    let dec_somme = p_decrypt(&c_somme, &keypair.public_key, &keypair.secret_key);
    let duree_dec = t.elapsed();
    println!("\n Déchiffrement : {:.3?}", duree_dec);
    println!("D(c1·c2 mod n²) = {}", dec_somme);

    if dec_somme == &m1 + &m2 {
        println!(" Homomorphisme additif vérifié : D(E(m1)·E(m2)) = m1 + m2");
    } else {
        println!(" Erreur dans l'homomorphisme additif !");
    }

    // --- Résumé des temps -----------------------------------------------
    println!("\n==============================================");
    println!("    RÉSUMÉ DES TEMPS — Paillier");
    println!("==============================================");
    match duree_keygen {
        Some(d) => println!("  Génération des clés      : {:.3?}  (nouvelle génération)", d),
        None    => println!("  Génération des clés      : —  (clés chargées depuis le disque)"),
    }
    println!("  Chiffrement m1           : {:.3?}", duree_enc_m1);
    println!("  Chiffrement m2           : {:.3?}", duree_enc_m2);
    println!("  Addition homomorphique   : {:.3?}", duree_add_homo);
    println!("  Déchiffrement            : {:.3?}", duree_dec);
    println!("==============================================");

    println!("\n==============================================");
    println!("    Fin de la démonstration Paillier");
    println!("==============================================");
}


// =====================================================================
//  DÉMONSTRATION FIORE-CATALANO
// =====================================================================

fn demonstration_fiore_catalano() {
    println!("\n==============================================");
    println!("  Cryptosystème Fiore-Catalano - Démonstration");
    println!("==============================================");

    // --- Clés (réutilisées si déjà générées) ----------------------------
	// ici les 3072 permet d'afin à l'écran le nombre de bits sur lequel, on travaille
	let (keypair, duree_keygen) = charger_ou_generer_cles(2048);

    afficher_cles(&keypair);

    // --- Messages et masques aléatoires ---------------------------------
    let one = BigUint::from(1u32);
    let mut rng = OsRng;

    let half_bits = &keypair.public_key.n.bits()/2;
    let bound = BigUint::from(1u32)<< half_bits as usize;

    let m1 = rng.gen_biguint_below(&bound);
    let m2 = rng.gen_biguint_below(&bound);
    let b1 = rng.gen_biguint_below(&bound);
    let b2 = rng.gen_biguint_below(&bound);

    println!("\nm1 = {}", m1);
    println!("m2 = {}", m2);

    // --- Chiffrement Fiore-Catalano m1 ----------------------------------
    let t = Instant::now();
    let cf1 = cf_encrypt(&m1, &b1, &keypair.public_key);
    let duree_enc_cf1 = t.elapsed();

    // --- Chiffrement Fiore-Catalano m2 ----------------------------------
    let t = Instant::now();
    let cf2 = cf_encrypt(&m2, &b2, &keypair.public_key);
    let duree_enc_cf2 = t.elapsed();

    println!("\n⏱  Chiffrement CF m1 : {:.3?}", duree_enc_cf1);
    println!("⏱  Chiffrement CF m2 : {:.3?}", duree_enc_cf2);

    // --- FORME 1 : Addition homomorphique CF ----------------------------
    println!("\n==================================");
    println!("  FORME 1 — Addition homomorphique");
    println!("==================================");

    let t = Instant::now();
    let first_form = cf_add(&cf1, &cf2);
    let duree_cf_add = t.elapsed();
    println!("⏱  Addition CF     : {:.3?}", duree_cf_add);
    println!("First Form CF      : {:?}", first_form);

    let t = Instant::now();
    let dec_first_form = cf_add_dec(&cf1, &keypair.public_key, &keypair.secret_key);
    let duree_cf_add_dec = t.elapsed();
    println!(" Déchiffrement addition CF : {:.3?}", duree_cf_add_dec);
    println!("Déchiffrement First Form     : {:?}", dec_first_form);

    // --- FORME 2 : Multiplication homomorphique CF ----------------------
    println!("\n==================================");
    println!("  FORME 2 — Multiplication homomorphique");
    println!("==================================");

    let t = Instant::now();
    let second_form = cf_mul(&cf1, &cf2, &keypair.public_key);
    let duree_cf_mul = t.elapsed();
    println!(" Multiplication CF         : {:.3?}", duree_cf_mul);
    println!("Second Form CF               : {:?}", second_form);

    let t = Instant::now();
    let dec_second_form = cf_mul_dec(&second_form, &keypair.public_key, &keypair.secret_key);
    let duree_cf_mul_dec = t.elapsed();
    println!("Déchiffrement multiplication CF : {:.3?}", duree_cf_mul_dec);
    println!("Déchiffrement Second Form          : {:?}", dec_second_form);

    // --- Résumé des temps -----------------------------------------------
    println!("\n==============================================");
    println!("    RÉSUMÉ DES TEMPS — Fiore-Catalano");
    println!("==============================================");
    match duree_keygen {
        Some(d) => println!("  Génération des clés           : {:.3?}  (nouvelle génération)", d),
        None    => println!("  Génération des clés           : —  (clés chargées depuis le disque)"),
    }
    println!("  Chiffrement CF m1             : {:.3?}", duree_enc_cf1);
    println!("  Chiffrement CF m2             : {:.3?}", duree_enc_cf2);
    println!("  Addition homomorphique CF     : {:.3?}", duree_cf_add);
    println!("  Déchiffrement addition CF     : {:.3?}", duree_cf_add_dec);
    println!("  Multiplication homomorphique  : {:.3?}", duree_cf_mul);
    println!("  Déchiffrement multiplication  : {:.3?}", duree_cf_mul_dec);
    println!("==============================================");

    println!("\n==============================================");
    println!("    Fin de la démonstration Fiore-Catalano");
    println!("==============================================");
}