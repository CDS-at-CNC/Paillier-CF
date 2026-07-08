// =========================================================
// src/bin/client.rs — Client PSI ExactMatch (H1 ou H2)
//
// VARIANTE CREUSE, positions en clair côté serveur (rapide) :
// matching sur adresse EMAIL (colonne CSV auto-détectée).
//
//   H1 (--bd 1) : DÉTENTEUR de la clé.
//     - génère l'UNIQUE paire Paillier (pk, sk) ; sk reste locale
//     - envoie pk au serveur (:7001)
//     - chiffre SES Ft (positions actives seulement) sous pk et les envoie
//     - reçoit le résultat agrégé (:7003), déchiffre -> cardinal EXACT
//     - identifie LOCALEMENT les patients en commun (par email)
//
//   H2 (--bd 2) : CHIFFREUR seulement.
//     - se connecte au serveur (:7002)
//     - reçoit pk_H1 (relayée par le serveur)
//     - chiffre SES Ft sous pk_H1 et les envoie
//     - n'apprend RIEN (pas de clé secrète, pas de résultat)
//
// Usage :
//   client --bd 1 --csv <fichier.csv> [--bits 512] [--email-col <nom>]
//   client --bd 2 --csv <fichier.csv> [--email-col <nom>]
//
// La colonne email est auto-détectée (email, mail, e-mail, adresse
// mail, adresse électronique, courriel, mél, ...). En cas d'échec,
// utiliser --email-col pour l'imposer explicitement.
// =========================================================

use std::env;
use std::net::{TcpListener, TcpStream};
use std::io;
use std::fs;
use std::time::Instant;

use paillier_crypto::exactmatch::{
    load_ids_from_csv,
    phase0_keygen, phase1_build_table,
    phase2_prepare_ft, phase4_decrypt_aggregate,
    FtBundle, AggResult,
};
use paillier_crypto::paillier::p_keygen::PublicKey;
use paillier_crypto::net_protocol::{
    BandwidthMeter,
    MsgPubKey, MsgFtBundle, MsgAgg,
    send_tracked, recv_tracked,
};

const SERVER_H1: &str = "127.0.0.1:7001";
const SERVER_H2: &str = "127.0.0.1:7002";
const LISTEN_H1: u16  = 7003;   // port sur lequel H1 reçoit le résultat agrégé

// Dossier de sortie des résultats PSI (cardinal + patients en commun).
const OUTPUT_DIR: &str = "src/dataFromPSI";

// Taille (bits) de CHAQUE facteur premier p, q  ->  |n| = 2 * bits.
// PoC : 512 pour une génération rapide. À augmenter pour la production.
const DEFAULT_BITS: u64 = 512;

// ─────────────────────────────────────────────────────────
// Log DevOps : affiche un échantillon des N premiers chiffrés
// (position, c0, c1) produits par CE côté (H1 ou H2). Chaque hôpital
// utilise son propre aléa (masque b + aléa Paillier r) : les
// chiffrés de H1 et de H2 sont donc TOUJOURS différents, même pour
// des valeurs identiques — propriété de sécurité sémantique de
// Paillier. Préfixe "[CIPHERTEXT]" pour capture facile côté frontend.
// ─────────────────────────────────────────────────────────
fn log_ciphertext_sample(label: &str, bundle: &FtBundle, n: usize) {
    let mut entries: Vec<(&usize, &(num_bigint::BigUint, num_bigint::BigUint))> =
        bundle.ft_by_pos.iter().collect();
    entries.sort_by_key(|(pos, _)| **pos);

    let shown = n.min(entries.len());
    println!(
        "[{}] --- Echantillon des {} premiers chiffres (log DevOps, capture frontend) ---",
        label, shown
    );
    for (pos, (c0, c1)) in entries.into_iter().take(n) {
        println!("[CIPHERTEXT] hopital={} pos={} c0={:x} c1={:x}", label, pos, c0, c1);
    }
}

fn pubkey_from_msg(msg: MsgPubKey) -> PublicKey {
    PublicKey { n: msg.n, g: msg.g, n_squared: msg.n_squared }
}

fn bundle_to_msg(b: &FtBundle) -> MsgFtBundle {
    MsgFtBundle {
        entries: b.ft_by_pos.iter().map(|(&pos, ft)| (pos, ft.clone())).collect(),
    }
}

fn arg_value<'a>(args: &'a [String], key: &str) -> Option<&'a String> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1))
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let bd_id: u8 = arg_value(&args, "--bd")
        .and_then(|v| v.parse().ok())
        .expect("Usage : client --bd <1|2> --csv <fichier.csv> [--bits N] [--email-col <nom>]");
    let csv_path: &str = arg_value(&args, "--csv")
        .map(String::as_str)
        .expect("Usage : client --bd <1|2> --csv <fichier.csv> [--bits N] [--email-col <nom>]");
    let bits: u64 = arg_value(&args, "--bits")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BITS);
    let email_col: Option<&str> = arg_value(&args, "--email-col").map(String::as_str);

    let label = if bd_id == 1 { "H1".to_string() } else { "H2".to_string() };

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║   CLIENT PSI — {} (matching email, positions claires)║", label);
    println!("╚══════════════════════════════════════════════════════╝\n");

    let mut meter = BandwidthMeter::new();
    let t_total   = Instant::now();

    let ids = load_ids_from_csv(csv_path, email_col);
    println!("[{}] {} identifiant(s) chargé(s) depuis {}.", label, ids.len(), csv_path);

    if bd_id == 1 {
        // ════════════════════════════ H1 ════════════════════════════
        // Phase 0a : génération de l'UNIQUE paire de clés.
        println!("\n[{}] Phase 0a : génération de la paire Paillier ({} bits/premier)...", label, bits);
        let kp = phase0_keygen(&label, bits);
        println!("[{}] Clé générée : |n| = {} bits, sk reste locale.", label, kp.public_key.n.bits());

        // Connexion au serveur.
        let mut stream = connect_retry(SERVER_H1, &label);

        // Phase 0a : envoi de pk (jamais sk).
        meter.begin("Phase 0a — envoi pk_H1");
        let pk_payload = MsgPubKey {
            n:         kp.public_key.n.clone(),
            g:         kp.public_key.g.clone(),
            n_squared: kp.public_key.n_squared.clone(),
        }.encode();
        send_tracked(&mut stream, &pk_payload, &mut meter)?;
        meter.end();
        println!("[{}] Phase 0a : pk envoyée ({} octets, sk NON envoyée).", label, pk_payload.len());

        // Phase 1 : table binaire creuse (position -> email conservé localement).
        println!("\n[{}] Phase 1 : construction de la table binaire...", label);
        let table = phase1_build_table(&label, &ids);

        // Phase 2 : Ft (positions actives) sous SA PROPRE clé publique.
        let bundle = phase2_prepare_ft(&label, &table, &kp.public_key);
        log_ciphertext_sample(&label, &bundle, 10);
        meter.begin("Phase 2 — envoi bundle");
        let bundle_payload = bundle_to_msg(&bundle).encode();
        send_tracked(&mut stream, &bundle_payload, &mut meter)?;
        meter.end();
        println!("[{}] Phase 2 terminée — {:.1} Ko envoyés.", label, bundle_payload.len() as f64 / 1024.0);

        // Phase 3 : réception du résultat AGRÉGÉ (le serveur se connecte à :7003).
        println!("\n[{}] Phase 3 : ouverture :{} pour recevoir le résultat agrégé...", label, LISTEN_H1);
        let listener = TcpListener::bind(format!("127.0.0.1:{}", LISTEN_H1))?;
        meter.begin("Phase 3 — réception résultat agrégé");
        let (mut ret, _) = listener.accept()?;
        let buf = recv_tracked(&mut ret, &mut meter)?;
        meter.end();
        let msg = MsgAgg::decode(&buf)?;
        let agg = AggResult { c0_agg: msg.c0_agg, b_prime_enc: msg.b_prime_enc };
        println!(
            "[{}] Phase 3 terminée — 1 chiffré agrégé + {} Enc(b') ({:.1} Ko).",
            label, agg.b_prime_enc.len(), buf.len() as f64 / 1024.0
        );

        // Phase 4 : terme croisé + 2 Dec (sk locale) + identification locale.
        println!("\n[{}] Phase 4 : terme croisé homomorphe + 2 Dec Paillier + identification...", label);
        meter.begin("Phase 4 — déchiffrement + identification");
        let result = phase4_decrypt_aggregate(&label, &agg, &bundle, &table, &kp);
        meter.end();

        println!("\n╔══════════════════════════════════════════════════════╗");
        println!("║  {} — RÉSULTAT (asymétrique : seul H1 le connaît)   ║", label);
        println!("╠══════════════════════════════════════════════════════╣");
        println!("║  |H1 ∩ H2|  =  {}", result.cardinal);
        println!("║  Temps total :  {:.3?}", t_total.elapsed());
        println!("╚══════════════════════════════════════════════════════╝");
        println!(
            "\n[{}] {} patient(s) en commun identifie(s) (detail dans le CSV exporte ci-dessous).",
            label, result.matched_ids.len()
        );

        // ── Export CSV : cardinal + emails en commun -> src/dataFromPSI ──
        fs::create_dir_all(OUTPUT_DIR).unwrap_or_else(|e| {
            panic!("Impossible de creer le dossier {} : {}", OUTPUT_DIR, e)
        });
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("horloge systeme invalide")
            .as_secs();
        let out_path = format!("{}/psi_result_{}.csv", OUTPUT_DIR, ts);

        let mut csv_content = format!("La taille de l'intersection,{}\n", result.cardinal);
        for (i, email) in result.matched_ids.iter().enumerate() {
            csv_content.push_str(&format!("{},{}\n", i + 1, email));
        }
        fs::write(&out_path, csv_content).unwrap_or_else(|e| {
            panic!("Impossible d'ecrire {} : {}", out_path, e)
        });
        println!("\n[{}] Resultat exporte -> {}", label, out_path);

    } else {
        // ════════════════════════════ H2 ════════════════════════════
        // Aucune génération de clé : H2 utilise pk_H1.
        let mut stream = connect_retry(SERVER_H2, &label);

        // Phase 0b : réception de pk_H1 relayée par le serveur.
        meter.begin("Phase 0b — réception pk_H1");
        let pk_buf = recv_tracked(&mut stream, &mut meter)?;
        meter.end();
        let pk_h1: PublicKey = pubkey_from_msg(MsgPubKey::decode(&pk_buf)?);
        println!("[{}] Phase 0b : pk_H1 reçue (|n| = {} bits).", label, pk_h1.n.bits());

        // Phase 1 : table binaire creuse.
        println!("\n[{}] Phase 1 : construction de la table binaire...", label);
        let table = phase1_build_table(&label, &ids);

        // Phase 2 : Ft (positions actives) sous pk_H1.
        let bundle = phase2_prepare_ft(&label, &table, &pk_h1);
        log_ciphertext_sample(&label, &bundle, 10);
        meter.begin("Phase 2 — envoi bundle");
        let bundle_payload = bundle_to_msg(&bundle).encode();
        send_tracked(&mut stream, &bundle_payload, &mut meter)?;
        meter.end();
        println!("[{}] Phase 2 terminée — {:.1} Ko envoyés.", label, bundle_payload.len() as f64 / 1024.0);

        println!("\n[{}] Terminé. H2 n'apprend RIEN (pas de sk, pas de résultat).", label);
        println!("[{}] Temps total : {:.3?}", label, t_total.elapsed());
    }

    meter.report();
    Ok(())
}

// ─────────────────────────────────────────────────────────
// Connexion au serveur avec retry (le serveur peut démarrer après).
// ─────────────────────────────────────────────────────────
fn connect_retry(addr: &str, label: &str) -> TcpStream {
    println!("[{}] Connexion au serveur {}...", label, addr);
    loop {
        match TcpStream::connect(addr) {
            Ok(s)  => { println!("[{}] Connecté.", label); return s; }
            Err(_) => {
                eprint!(".");
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}
