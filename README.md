# PSI-ExactMatch — Paillier + Catalano-Fiore

Bibliothèque Rust implémentant un protocole de **Private Set Intersection (PSI) à cardinalité exacte**, combinant le cryptosystème de **Paillier** (chiffrement homomorphe additif) et le schéma de **Catalano-Fiore** (multiplication homomorphe depth-1), pour calculer l'intersection entre deux bases de données (patients, contacts CRM, etc.) sans que ni le serveur ni l'une des deux parties n'accède aux données en clair de l'autre.

> **Statut : PoC / MVP.**

---

## Sommaire

- [Modèle du protocole](#modèle-du-protocole)
- [Les 4 phases](#les-4-phases)
- [Structure du dépôt](#structure-du-dépôt)
- [Prérequis](#prérequis)
- [Utilisation — binaires Rust](#utilisation--binaires-rust)
- [Format des fichiers d'entrée (CSV)](#format-des-fichiers-dentrée-csv)
- [Résultat de sortie](#résultat-de-sortie)
- [Logs DevOps — chiffrés échantillon](#logs-devops--chiffrés-échantillon)
- [Bindings Python (PyO3 / maturin)](#bindings-python-pyo3--maturin)
- [Paramètres à durcir avant production](#paramètres-à-durcir-avant-production)
- [Roadmap](#roadmap)

---

## Modèle du protocole

Architecture **mono-clé asymétrique** : un seul des deux hôpitaux détient la paire de clés Paillier, ce qui garantit que **seul lui obtient le résultat**.

| Rôle | Détient `sk` | Ce qu'il apprend |
|---|---|---|
| **H1** (récepteur) | ✅ Oui | Cardinal exact de l'intersection **+** identité des patients en commun |
| **H2** (émetteur) | ❌ Non | Rien — H2 chiffre et envoie, sans jamais recevoir de résultat |
| **Serveur** (tiers de calcul) | ❌ Non | Voit les positions chiffrés mais jamais les valeurs en clair déchiffrées, ni `sk` |

```
H1 ──pk_H1──▶ Serveur ──pk_H1──▶ H2
H1 ──Ft_H1──▶ Serveur ◀──Ft_H2── H2
                 │
         (CF.Mul + agrégation)
                 │
                 ▼
              H1 (déchiffre, identifie)
```

## Les 4 phases

| Phase | Acteur | Action |
|---|---|---|
| **0** | H1 | Génère l'unique paire de clés Paillier (`pk`, `sk`) ; envoie `pk` au serveur, qui la relaie à H2. `sk` ne quitte jamais H1. |
| **1** | H1, H2 | Construit une table binaire creuse : `t[h(email)] = 1` pour chaque identifiant. |
| **2** | H1, H2 | Chiffre les positions actives via Catalano-Fiore (première forme) sous `pk` de H1. |
| **3** | Serveur | Calcule sur les positions reçue au format CF1, applique `CF.Mul` sur les positions reçues, agrège en un seul chiffré Paillier (`C0_agg`) + collecte les `Enc(b')`. Renvoie le tout à H1 uniquement. |
| **4** | H1 | Reconstruit le terme croisé par exponentiation homomorphe, déchiffre (2 opérations Paillier au lieu de `3k`) → cardinal exact. Identifie **localement** les patients communs par un simple lookup position → email (aucun calcul crypto supplémentaire). |

La construction mathématique complète est documentée dans `CHANGELOG_mono_cle_agrege.md`.

## Structure du dépôt

```
Paillier_v_mars/
├── Cargo.toml                    # dépendances + feature "python" (PyO3, optionnelle)
├── pyproject.toml                # config maturin (bindings Python)
├── PYTHON_BINDINGS.md            # doc complète des bindings PyO3
├── CHANGELOG_mono_cle_agrege.md  # historique détaillé des choix d'architecture
├── python_example/
│   └── psi_demo.py               # exemple d'orchestration des 4 phases en Python
├── src/
│   ├── main.rs                   # binaire interactif (menu + métriques Paillier)
│   ├── lib.rs                    # racine de la bibliothèque
│   ├── pybindings.rs             # bindings PyO3 (compilé avec --features python)
│   ├── bin/
│   │   ├── server.rs             # binaire serveur PSI (tiers de calcul)
│   │   └── client.rs             # binaire client PSI (rôle H1 ou H2)
│   ├── exactmatch/                # cœur du protocole PSI (table, phases 1-4)
│   ├── paillier/                  # keygen, encrypt, decrypt, primitives math
│   ├── fiore_catalano/            # CF.Enc, CF.Mul, CF.Add
│   ├── net_protocol/              # sérialisation réseau + mesure de bande passante
│   ├── crypto_error/              # erreur centralisée CryptoError
│   ├── base de donnes/            # jeux de données CSV de test (NSS)
│   └── dataFromPSI/                # résultats exportés (cardinal + emails communs)
```

## Prérequis

- Rust stable (`cargo`)
- Pour les bindings Python : `pip install maturin` (voir `PYTHON_BINDINGS.md`)

## Utilisation — binaires Rust

Trois terminaux, depuis la racine du projet (là où se trouve `Cargo.toml`) :

```bash
# Terminal 1 — serveur
cargo run --release --bin server

# Terminal 2 — H1 (détient la clé, obtient le résultat)
cargo run --release --bin client -- --bd 1 --csv <fichier_H1.csv>

# Terminal 3 — H2 (chiffre sous pk_H1, n'apprend rien)
cargo run --release --bin client -- --bd 2 --csv <fichier_H2.csv>
```

Options de `client` :

| Flag | Rôle | Défaut |
|---|---|---|
| `--bd <1\|2>` | Rôle joué (H1 ou H2) | requis |
| `--csv <chemin>` | Fichier source | requis |
| `--bits <n>` | Taille (bits) de chaque facteur premier Paillier | `512` (PoC — à augmenter en prod) |
| `--email-col <nom>` | Impose le nom exact de la colonne email si l'auto-détection échoue | auto-détection |

## Format des fichiers d'entrée (CSV)

Le matching se fait sur l'**adresse email**. La colonne est **auto-détectée** parmi les libellés courants (`email`, `mail`, `e-mail`, `adresse mail`, `adresse électronique`, `courriel`, `mél`, etc., insensible à la casse et aux accents). Si aucun de ces libellés ne correspond, utilisez `--email-col "<nom exact>"`.

Les emails sont normalisés en minuscules au chargement (comparaison insensible à la casse).

## Résultat de sortie

À la fin de la Phase 4, **H1** écrit automatiquement `src/dataFromPSI/psi_result_<timestamp_unix>.csv` :

```csv
La taille de l'intersection,1500
1,julia.thomas@nexora.com
2,nina.laurent@yahoo.fr
...
```

## Logs DevOps — chiffrés échantillon

Après la Phase 2, chaque hôpital (H1 et H2, indépendamment) affiche ses 10 premiers chiffrés produits, triés par position :

```
[CIPHERTEXT] hopital=H1 pos=1234 c0=<hex> c1=<hex>
[CIPHERTEXT] hopital=H2 pos=5678 c0=<hex> c1=<hex>
```

Préfixe `[CIPHERTEXT]` volontairement distinctif pour une capture facile côté pipeline de logs (grep/parsing). Par construction (aléa Paillier + masque propres à chaque hôpital), les chiffrés de H1 et H2 sont **toujours différents**, même pour des positions ou valeurs identiques — propriété de sécurité sémantique de Paillier.

## Bindings Python (PyO3 / maturin)

Le protocole est également exposé comme module Python (`import paillier_crypto`), pour intégration dans un backend Python (jobs, orchestration, computation modules) :

```bash
pip install maturin
maturin develop --features python
```

Couvre les primitives Paillier directes, les 4 phases PSI, l'échantillon de chiffrés DevOps, et une exception centralisée `PsiCryptoError`. **Voir `PYTHON_BINDINGS.md` pour la référence API complète** (classes, signatures, modèle d'erreurs, check-list d'intégration par rôle).


## Paramètres à durcir avant production

| Paramètre | Valeur PoC actuelle | Recommandation production |
|---|---|---|
| `MIN_KEY_BITS` (`src/paillier/math/math.rs`) | 512 bits/premier (`\|n\|=1024`) | ≥ 1536-2048 bits/premier |
| `HASH_BITS` / `TABLE_SIZE` (`src/exactmatch/exactmatch.rs`) | `2^14 = 16384` | À dimensionner selon `n` max attendu |
| Fonction de hash (`simple_hash`) | Non cryptographique, non salée | SHA-256/BLAKE3 + sel partagé, ou passer à la variante bucket+comparaison exacte déjà présente dans le code |
| Canal réseau (`net_protocol.rs`) | TCP en clair, pas d'authentification de `pk` relayée | TLS + authentification mutuelle |

## Roadmap

- Conversion complète des 4 fonctions de phase PSI en `Result<_, CryptoError>` (élimine le dernier filet de sécurité basé sur les panics)
- Activation de la feature `abi3` pour des wheels Python forward-compatibles
- Configuration `manylinux` pour des wheels Linux portables
- Réactivation de la variante « bucket + comparaison exacte » si un modèle de menace plus strict est requis côté serveur
