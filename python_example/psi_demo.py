"""
Exemple d'utilisation des bindings PyO3 (paillier_crypto) depuis un
backend Python — protocole PSI-ExactMatch complet en un seul process
(à des fins de démonstration ; en production, H1 / H2 / le serveur
sont typiquement 3 services séparés qui échangent les objets
sérialisés via .to_wire() / .from_wire() sur le réseau de votre choix
— HTTP, gRPC, websocket, etc., peu importe : ces bindings ne prennent
aucune décision de transport, ils exposent uniquement le calcul.)

Build local :
    pip install maturin
    maturin develop --features python      # installe le module dans le venv actif
"""

import time
import paillier_crypto as psi


def log_ciphertexts(label: str, bundle) -> None:
    """Affiche les 10 premiers chiffrés d'un bundle — capture DevOps/frontend."""
    print(f"[{label}] --- Echantillon des 10 premiers chiffres ---")
    for pos, c0_hex, c1_hex in bundle.ciphertext_sample(10):
        print(f"[CIPHERTEXT] hopital={label} pos={pos} c0={c0_hex} c1={c1_hex}")


def run_demo():
    emails_h1 = ["a@x.com", "b@x.com", "commun1@x.com", "commun2@x.com"]
    emails_h2 = ["c@x.com", "d@x.com", "commun1@x.com", "commun2@x.com"]

    # ── Phase 0 : H1 génère l'UNIQUE paire de clés ──────────────────────
    try:
        kp_h1 = psi.paillier_keygen(512)  # bits/premier ; augmenter en production
    except psi.PsiCryptoError as e:
        print(f"Erreur keygen : {e}")
        return

    pk_h1 = kp_h1.public_key
    print(f"[H1] Clé générée : {pk_h1!r}")

    # ── Phase 1 : chaque côté construit sa table ────────────────────────
    table_h1 = psi.psi_phase1_build_table("H1", emails_h1)
    table_h2 = psi.psi_phase1_build_table("H2", emails_h2)

    # ── Phase 2 : chaque côté chiffre ses positions actives ─────────────
    bundle_h1 = psi.psi_phase2_prepare_ft("H1", table_h1, pk_h1)
    bundle_h2 = psi.psi_phase2_prepare_ft("H2", table_h2, pk_h1)  # sous pk de H1

    # Logs DevOps : 10 premiers chiffrés de CHAQUE côté (toujours différents).
    log_ciphertexts("H1", bundle_h1)
    log_ciphertexts("H2", bundle_h2)

    # (Ici, en production : bundle_h1.to_wire() / bundle_h2.to_wire() partent
    #  sur le réseau vers le service "serveur", qui les reconstruit via
    #  PyFtBundle.from_wire(...).)

    # ── Phase 3 : le serveur agrège (ne détient QUE pk, jamais sk) ──────
    agg = psi.psi_phase3_server_aggregate(table_h1, table_h2, bundle_h1, bundle_h2, pk_h1)

    # ── Phase 4 : H1 déchiffre + identifie localement les patients communs ──
    try:
        result = psi.psi_phase4_decrypt_aggregate("H1", agg, bundle_h1, table_h1, kp_h1)
    except psi.PsiCryptoError as e:
        print(f"Erreur Phase 4 : {e}")
        return

    print(f"\nCardinal exact |H1 ∩ H2| = {result.cardinal}")
    print(f"Patients en commun : {result.matched_ids}")

    # ── Export CSV (même format que côté binaire Rust) ──────────────────
    ts = int(time.time())
    out_path = f"src/dataFromPSI/psi_result_{ts}.csv"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"La taille de l'intersection,{result.cardinal}\n")
        for i, email in enumerate(result.matched_ids, start=1):
            f.write(f"{i},{email}\n")
    print(f"Resultat exporte -> {out_path}")


def demo_error_handling():
    """Illustre la remontée d'erreur propre (pas de crash process)."""
    try:
        # bits=10 est en-dessous du minimum -> KeySizeTooSmall
        psi.paillier_keygen(10)
    except psi.PsiCryptoError as e:
        print(f"Erreur capturee proprement (pas de crash) : {e}")


if __name__ == "__main__":
    demo_error_handling()
    run_demo()
