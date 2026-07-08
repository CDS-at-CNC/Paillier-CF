// =========================================================
// src/bin/server.rs — Serveur PSI ExactMatch (v3 : creux, positions en clair)
//
// Compromis assumé (demandé explicitement) : le serveur compare les
// positions EN CLAIR pour déterminer l'intersection — rapide, et
// permet à H1 d'identifier les patients en commun (pas seulement
// leur nombre). Le calcul du cardinal reste malgré tout fait via
// Paillier/Catalano-Fiore (2 déchiffrements agrégés), conformément
// à la construction du rapport de référence CEA/ClickNCrypt.
//
// Modèle :
//   - H1 détient l'UNIQUE paire de clés. Il envoie SA clé publique
//     au serveur (Phase 0a) qui la relaie à H2 (Phase 0b).
//   - H1 et H2 envoient leurs Ft (1ère forme CF) chiffrés sous pk_H1
//     (Phase 2), UNIQUEMENT pour leurs positions actives (creux).
//   - Le serveur compare les positions EN CLAIR (common_positions),
//     applique CF.Mul (2nde forme) sous pk_H1 sur ces positions, puis
//     AGRÈGE : c0_agg = ∏_p C0_p mod N² (un seul chiffré Paillier),
//     et collecte les Enc(b'_p) de H2 (= c1'_p) pour le terme croisé.
//   - Le serveur renvoie (c0_agg, [Enc(b'_p)]) à H1 UNIQUEMENT (asymétrie).
//     Il ne détient PAS sk : il ne déchiffre rien lui-même.
//
// Ports :
//   :7001  H1 -> Serveur   (pk_H1 puis bundle H1)
//   :7002  H2 -> Serveur   (bundle H2, après réception de pk_H1)
//   :7003  Serveur -> H1   (résultat agrégé)
// =========================================================

use std::net::{TcpListener, TcpStream};
use std::io;
use std::time::Instant;
use std::collections::HashSet;

use paillier_crypto::exactmatch::{
    SparseTable, FtBundle, phase3_server_aggregate,
};
use paillier_crypto::paillier::p_keygen::PublicKey;
use paillier_crypto::net_protocol::{
    BandwidthMeter,
    MsgPubKey, MsgFtBundle, MsgAgg,
    send_tracked, recv_tracked,
};

const PORT_H1:     u16  = 7001;
const PORT_H2:     u16  = 7002;
const RETURN_H1:   &str = "127.0.0.1:7003";

// ─────────────────────────────────────────────────────────
// Reçoit un MsgFtBundle et reconstruit (FtBundle, SparseTable).
//
// Table creuse : les clés reçues SONT les positions actives — le
// serveur les voit en clair (compromis assumé pour la rapidité et
// l'identification des patients).
// ─────────────────────────────────────────────────────────
fn recv_bundle(
    stream: &mut TcpStream,
    label:  &str,
    meter:  &mut BandwidthMeter,
) -> io::Result<(FtBundle, SparseTable)> {
    meter.begin(&format!("Phase2 recv {}", label));
    let buf = recv_tracked(stream, meter)?;
    meter.end();

    let msg = MsgFtBundle::decode(&buf)?;
    let ft_by_pos: std::collections::HashMap<usize, (num_bigint::BigUint, num_bigint::BigUint)> =
        msg.entries.into_iter().collect();
    let active: HashSet<usize> = ft_by_pos.keys().copied().collect();

    println!("[Serveur] {} Phase 2 : {} position(s) active(s) reçue(s).", label, ft_by_pos.len());
    // position_to_id : le serveur ne connaît pas les identifiants d'origine,
    // seulement les positions (hash) — cette table reste vide côté serveur.
    Ok((FtBundle { ft_by_pos }, SparseTable { active, position_to_id: Default::default() }))
}

fn main() -> io::Result<()> {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║   SERVEUR PSI — creux, positions en clair (clé H1)    ║");
    println!("║   H1→:7001   H2→:7002   retour H1→:7003              ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    let mut meter1 = BandwidthMeter::new(); // trafic H1 ↔ Serveur
    let mut meter2 = BandwidthMeter::new(); // trafic H2 ↔ Serveur

    // ── Phase 0a : H1 se connecte et envoie pk_H1 ───────────────────
    let listener_h1 = TcpListener::bind(format!("127.0.0.1:{}", PORT_H1))?;
    println!("[Serveur] En attente de H1 sur :{}...", PORT_H1);
    let (mut stream_h1, _) = listener_h1.accept()?;
    println!("[Serveur] H1 connecté depuis {:?}", stream_h1.peer_addr()?);

    meter1.begin("Phase0a recv pk_H1");
    let pk_buf = recv_tracked(&mut stream_h1, &mut meter1)?;
    meter1.end();
    let msg = MsgPubKey::decode(&pk_buf)?;
    let pk_h1 = PublicKey { n: msg.n, g: msg.g, n_squared: msg.n_squared };
    println!("[Serveur] Phase 0a : pk_H1 reçue (|n|={} bits).", pk_h1.n.bits());

    // ── H2 se connecte ──────────────────────────────────────────────
    let listener_h2 = TcpListener::bind(format!("127.0.0.1:{}", PORT_H2))?;
    println!("[Serveur] En attente de H2 sur :{}...", PORT_H2);
    let (mut stream_h2, _) = listener_h2.accept()?;
    println!("[Serveur] H2 connecté depuis {:?}", stream_h2.peer_addr()?);

    // ── Phase 0b : relais de pk_H1 vers H2 ──────────────────────────
    meter2.begin("Phase0b send pk_H1 to H2");
    let relay = MsgPubKey {
        n:         pk_h1.n.clone(),
        g:         pk_h1.g.clone(),
        n_squared: pk_h1.n_squared.clone(),
    }.encode();
    send_tracked(&mut stream_h2, &relay, &mut meter2)?;
    meter2.end();
    println!("[Serveur] Phase 0b : pk_H1 relayée à H2 ({} octets).", relay.len());

    // ── Phase 2 : réception des bundles (H1 puis H2) ────────────────
    println!("[Serveur] Phase 2 : réception des bundles...");
    let (bundle1, table1) = recv_bundle(&mut stream_h1, "H1", &mut meter1)?;
    let (bundle2, table2) = recv_bundle(&mut stream_h2, "H2", &mut meter2)?;
    println!("[Serveur] Phase 2 terminée.");

    // ── Phase 3 : CF.Mul + AGRÉGATION ────────
    println!("[Serveur] Phase 3 : comparaison des positions + CF.Mul + agrégation (clé de H1)...");
    let t_p3 = Instant::now();
    let agg = phase3_server_aggregate(&table1, &table2, &bundle1, &bundle2, &pk_h1);
    let n_bprime = agg.b_prime_enc.len();
    println!(
        "[Serveur] Phase 3 en {:.3?} — 1 chiffré agrégé + {} Enc(b').",
        t_p3.elapsed(), n_bprime
    );

    // ── Phase 3 (envoi) : résultat agrégé vers H1 UNIQUEMENT ────────
    println!("[Serveur] Envoi du résultat agrégé → H1 ({})...", RETURN_H1);
    meter1.begin("Phase3 send H1");
    let payload = MsgAgg { c0_agg: agg.c0_agg, b_prime_enc: agg.b_prime_enc }.encode();
    let mut out = loop {
        match TcpStream::connect(RETURN_H1) {
            Ok(s)  => break s,
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    };
    send_tracked(&mut out, &payload, &mut meter1)?;
    meter1.end();
    println!(
        "[Serveur] Résultat agrégé envoyé à H1 ({:.1} Ko, {} Enc(b')). H2 ne reçoit RIEN.",
        payload.len() as f64 / 1024.0, n_bprime
    );

    println!("\n[Serveur] ─── Rapport H1 ↔ Serveur ───");
    meter1.report();
    println!("[Serveur] ─── Rapport H2 ↔ Serveur ───");
    meter2.report();

    Ok(())
}
