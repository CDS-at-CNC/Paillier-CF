// =========================================================
// net_protocol.rs — Protocole réseau PSI ExactMatch
//
// Sérialisation binaire des messages échangés entre BD1/BD2
// et le Serveur, avec instrumentation de la bande passante.
//
// Format de chaque message sur le socket :
//   [4 octets big-endian : longueur du payload]
//   [N octets : payload binaire (BigUint encodés en bytes BE)]
//
// Types de messages :
//   MsgPubKey       Phase 0  BD → Serveur  : clé publique (n, g, n²)
//   MsgBundle       Phase 2  BD → Serveur  : DualFtBundle sérialisé
//   MsgTriplets     Phase 3  Serveur → BD  : Vec<CfSnd>
//   MsgCardinal     Phase 4  BD → Serveur  : usize (résultat)
//
// Mesure de bande passante :
//   BandwidthMeter accumule les octets envoyés/reçus avec horodatage.
//   Un rapport final est imprimé à la fin du protocole.
// =========================================================

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use num_bigint::BigUint;

// ─────────────────────────────────────────────────────────
// Encodage / décodage d'un BigUint en bytes big-endian
// préfixé par 4 octets de longueur.
// ─────────────────────────────────────────────────────────

/// Encode un BigUint : [u32 BE longueur][bytes BE]
pub fn encode_biguint(n: &BigUint) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    let len = bytes.len() as u32;
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes);
    out
}

/// Décode un BigUint depuis un reader.
pub fn decode_biguint<R: Read>(r: &mut R) -> io::Result<BigUint> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Encode un (BigUint, BigUint) = CfFst
pub fn encode_cffst(c: &(BigUint, BigUint)) -> Vec<u8> {
    let mut out = encode_biguint(&c.0);
    out.extend(encode_biguint(&c.1));
    out
}

/// Décode un CfFst
pub fn decode_cffst<R: Read>(r: &mut R) -> io::Result<(BigUint, BigUint)> {
    let c0 = decode_biguint(r)?;
    let c1 = decode_biguint(r)?;
    Ok((c0, c1))
}

/// Encode un (BigUint, BigUint, BigUint) = CfSnd
pub fn encode_cfsnd(c: &(BigUint, BigUint, BigUint)) -> Vec<u8> {
    let mut out = encode_biguint(&c.0);
    out.extend(encode_biguint(&c.1));
    out.extend(encode_biguint(&c.2));
    out
}

/// Décode un CfSnd
pub fn decode_cfsnd<R: Read>(r: &mut R) -> io::Result<(BigUint, BigUint, BigUint)> {
    let c0 = decode_biguint(r)?;
    let c1 = decode_biguint(r)?;
    let c2 = decode_biguint(r)?;
    Ok((c0, c1, c2))
}

// ─────────────────────────────────────────────────────────
// Framing : envoi/réception d'un message avec en-tête 4 octets
// ─────────────────────────────────────────────────────────

/// Envoie un payload préfixé par sa longueur (u32 BE).
/// Retourne le nombre total d'octets écrits sur le socket.
pub fn send_msg<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<usize> {
    let len = payload.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(4 + payload.len())
}

/// Reçoit un message et retourne le payload + la taille totale lue.
pub fn recv_msg<R: Read>(r: &mut R) -> io::Result<(Vec<u8>, usize)> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok((buf, 4 + len))
}

// ─────────────────────────────────────────────────────────
// Messages de haut niveau
// ─────────────────────────────────────────────────────────

/// Phase 0 : une clé publique Paillier (n, g, n_squared)
pub struct MsgPubKey {
    pub n:         BigUint,
    pub g:         BigUint,
    pub n_squared: BigUint,
}

impl MsgPubKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_biguint(&self.n);
        out.extend(encode_biguint(&self.g));
        out.extend(encode_biguint(&self.n_squared));
        out
    }

    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        let n         = decode_biguint(&mut cur)?;
        let g         = decode_biguint(&mut cur)?;
        let n_squared = decode_biguint(&mut cur)?;
        Ok(MsgPubKey { n, g, n_squared })
    }
}

/// Phase 2 : un FtBundle = liste de (position: usize, CfFst)
/// On encode position en u64 BE.
pub struct MsgFtBundle {
    pub entries: Vec<(usize, (BigUint, BigUint))>,
}

impl MsgFtBundle {
    pub fn encode(&self) -> Vec<u8> {
        // Nombre d'entrées : u32 BE
        let count = self.entries.len() as u32;
        let mut out = count.to_be_bytes().to_vec();
        for (pos, ft) in &self.entries {
            // position : u64 BE
            out.extend_from_slice(&(*pos as u64).to_be_bytes());
            out.extend(encode_cffst(ft));
        }
        out
    }

    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        let mut count_buf = [0u8; 4];
        io::Read::read_exact(&mut cur, &mut count_buf)?;
        let count = u32::from_be_bytes(count_buf) as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let mut pos_buf = [0u8; 8];
            io::Read::read_exact(&mut cur, &mut pos_buf)?;
            let pos = u64::from_be_bytes(pos_buf) as usize;
            let ft  = decode_cffst(&mut cur)?;
            entries.push((pos, ft));
        }
        Ok(MsgFtBundle { entries })
    }
}

/// Phase 2 : DualFtBundle = bundle sous pk1 + bundle sous pk2
pub struct MsgDualBundle {
    pub under_pk1: MsgFtBundle,
    pub under_pk2: MsgFtBundle,
}

impl MsgDualBundle {
    pub fn encode(&self) -> Vec<u8> {
        let enc1 = self.under_pk1.encode();
        let enc2 = self.under_pk2.encode();
        // Préfixer chaque sous-bundle par sa taille
        let mut out = (enc1.len() as u32).to_be_bytes().to_vec();
        out.extend(enc1);
        out.extend((enc2.len() as u32).to_be_bytes());
        out.extend(enc2);
        out
    }

    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        let mut len_buf = [0u8; 4];
        io::Read::read_exact(&mut cur, &mut len_buf)?;
        let len1 = u32::from_be_bytes(len_buf) as usize;
        let mut b1 = vec![0u8; len1];
        io::Read::read_exact(&mut cur, &mut b1)?;
        let under_pk1 = MsgFtBundle::decode(&b1)?;

        io::Read::read_exact(&mut cur, &mut len_buf)?;
        let len2 = u32::from_be_bytes(len_buf) as usize;
        let mut b2 = vec![0u8; len2];
        io::Read::read_exact(&mut cur, &mut b2)?;
        let under_pk2 = MsgFtBundle::decode(&b2)?;

        Ok(MsgDualBundle { under_pk1, under_pk2 })
    }
}

/// Phase 3 : liste de CfSnd = Vec<(BigUint,BigUint,BigUint)>
pub struct MsgTriplets {
    pub triplets: Vec<(BigUint, BigUint, BigUint)>,
}

impl MsgTriplets {
    pub fn encode(&self) -> Vec<u8> {
        let count = self.triplets.len() as u32;
        let mut out = count.to_be_bytes().to_vec();
        for t in &self.triplets {
            out.extend(encode_cfsnd(t));
        }
        out
    }

    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        let mut count_buf = [0u8; 4];
        io::Read::read_exact(&mut cur, &mut count_buf)?;
        let count = u32::from_be_bytes(count_buf) as usize;
        let mut triplets = Vec::with_capacity(count);
        for _ in 0..count {
            triplets.push(decode_cfsnd(&mut cur)?);
        }
        Ok(MsgTriplets { triplets })
    }
}

// ─────────────────────────────────────────────────────────
// BandwidthMeter — compteur de bande passante par phase
// ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PhaseMetric {
    pub name:        String,
    pub bytes_sent:  usize,
    pub bytes_recv:  usize,
    pub duration:    Duration,
}

pub struct BandwidthMeter {
    pub metrics:     Vec<PhaseMetric>,
    phase_start:     Instant,
    current_phase:   String,
    cur_sent:        usize,
    cur_recv:        usize,
}

impl BandwidthMeter {
    pub fn new() -> Self {
        BandwidthMeter {
            metrics:       Vec::new(),
            phase_start:   Instant::now(),
            current_phase: String::from("init"),
            cur_sent:      0,
            cur_recv:      0,
        }
    }

    /// Démarre une nouvelle phase de mesure.
    pub fn begin(&mut self, phase: &str) {
        self.phase_start   = Instant::now();
        self.current_phase = phase.to_string();
        self.cur_sent      = 0;
        self.cur_recv      = 0;
    }

    /// Enregistre N octets envoyés dans la phase courante.
    pub fn add_sent(&mut self, n: usize) {
        self.cur_sent += n;
    }

    /// Enregistre N octets reçus dans la phase courante.
    pub fn add_recv(&mut self, n: usize) {
        self.cur_recv += n;
    }

    /// Clôt la phase courante et enregistre la métrique.
    pub fn end(&mut self) {
        self.metrics.push(PhaseMetric {
            name:       self.current_phase.clone(),
            bytes_sent: self.cur_sent,
            bytes_recv: self.cur_recv,
            duration:   self.phase_start.elapsed(),
        });
    }

    /// Affiche le rapport complet de bande passante.
    pub fn report(&self) {
        let total_sent: usize = self.metrics.iter().map(|m| m.bytes_sent).sum();
        let total_recv: usize = self.metrics.iter().map(|m| m.bytes_recv).sum();
        let total_dur:  Duration = self.metrics.iter().map(|m| m.duration).sum();

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║            RAPPORT BANDE PASSANTE — PSI ExactMatch               ║");
        println!("╠═══════════════════════╦══════════════╦══════════════╦════════════╣");
        println!("║ Phase                 ║   Envoyés    ║    Reçus     ║   Durée    ║");
        println!("╠═══════════════════════╬══════════════╬══════════════╬════════════╣");

        for m in &self.metrics {
            println!(
                "║ {:<21} ║ {:>9} o   ║ {:>9} o   ║ {:>8.3?} ║",
                m.name,
                m.bytes_sent,
                m.bytes_recv,
                m.duration
            );
        }

        println!("╠═══════════════════════╬══════════════╬══════════════╬════════════╣");
        println!(
            "║ {:<21} ║ {:>9} o   ║ {:>9} o   ║ {:>8.3?} ║",
            "TOTAL",
            total_sent,
            total_recv,
            total_dur
        );
        println!("╠═══════════════════════╩══════════════╩══════════════╩════════════╣");
        println!(
            "║  Total échangé  : {:>8} Ko  ({:.2} Mo)                              ║",
            (total_sent + total_recv) / 1024,
            (total_sent + total_recv) as f64 / (1024.0 * 1024.0)
        );

        // Débit moyen (évite la division par zéro)
        let secs = total_dur.as_secs_f64();
        if secs > 0.0 {
            let throughput_kb = (total_sent + total_recv) as f64 / 1024.0 / secs;
            println!(
                "║  Débit moyen    : {:>8.1} Ko/s                                       ║",
                throughput_kb
            );
        }
        println!("╚══════════════════════════════════════════════════════════════════╝\n");
    }
}

// ─────────────────────────────────────────────────────────
// Helpers send/recv instrumentés
// ─────────────────────────────────────────────────────────

/// Envoie un message ET met à jour le compteur de bande passante.
pub fn send_tracked(
    stream:  &mut TcpStream,
    payload: &[u8],
    meter:   &mut BandwidthMeter,
) -> io::Result<()> {
    let n = send_msg(stream, payload)?;
    meter.add_sent(n);
    Ok(())
}

/// Reçoit un message ET met à jour le compteur de bande passante.
pub fn recv_tracked(
    stream: &mut TcpStream,
    meter:  &mut BandwidthMeter,
) -> io::Result<Vec<u8>> {
    let (buf, n) = recv_msg(stream)?;
    meter.add_recv(n);
    Ok(buf)
}
// ─────────────────────────────────────────────────────────
// Phase 3 (AGRÉGÉE, Option 2) : chiffré C0 agrégé + Enc(b') par position
//   Envoyé par le serveur à H1 UNIQUEMENT.
// ─────────────────────────────────────────────────────────
pub struct MsgAgg {
    pub c0_agg:      BigUint,
    pub b_prime_enc: Vec<(usize, BigUint)>,
}

impl MsgAgg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_biguint(&self.c0_agg);
        let count = self.b_prime_enc.len() as u32;
        out.extend_from_slice(&count.to_be_bytes());
        for (pos, enc) in &self.b_prime_enc {
            out.extend_from_slice(&(*pos as u64).to_be_bytes());
            out.extend(encode_biguint(enc));
        }
        out
    }

    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        let c0_agg = decode_biguint(&mut cur)?;
        let mut count_buf = [0u8; 4];
        io::Read::read_exact(&mut cur, &mut count_buf)?;
        let count = u32::from_be_bytes(count_buf) as usize;
        let mut b_prime_enc = Vec::with_capacity(count);
        for _ in 0..count {
            let mut pos_buf = [0u8; 8];
            io::Read::read_exact(&mut cur, &mut pos_buf)?;
            let pos = u64::from_be_bytes(pos_buf) as usize;
            let enc = decode_biguint(&mut cur)?;
            b_prime_enc.push((pos, enc));
        }
        Ok(MsgAgg { c0_agg, b_prime_enc })
    }
}

// ─────────────────────────────────────────────────────────
// VARIANTE EXACT-MATCH : message générique (position, BigUint).
//   - H1/H2 → Serveur (Phase 2) : (position, Enc_pk(m_p))
//   - Serveur → H1    (Phase 3) : (position, D_p) = test d'égalité aveuglé
// Un seul type suffit pour les deux usages (même forme sur le fil).
// ─────────────────────────────────────────────────────────
pub struct MsgPosValues {
    pub entries: Vec<(usize, BigUint)>,
}

impl MsgPosValues {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let count = self.entries.len() as u32;
        out.extend_from_slice(&count.to_be_bytes());
        for (pos, v) in &self.entries {
            out.extend_from_slice(&(*pos as u64).to_be_bytes());
            out.extend(encode_biguint(v));
        }
        out
    }

    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        let mut count_buf = [0u8; 4];
        cur.read_exact(&mut count_buf)?;
        let count = u32::from_be_bytes(count_buf) as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let mut pos_buf = [0u8; 8];
            cur.read_exact(&mut pos_buf)?;
            let pos = u64::from_be_bytes(pos_buf) as usize;
            let v = decode_biguint(&mut cur)?;
            entries.push((pos, v));
        }
        Ok(MsgPosValues { entries })
    }
}
