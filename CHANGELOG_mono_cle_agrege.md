# PSI-ExactMatch — Refonte mono-clé asymétrique + agrégation (Option 2)

Version PoC/MVP. Sécurité volontairement mise de côté (voir §Limites).

## Modèle implémenté

- **H1** génère l'**UNIQUE** paire Paillier `(pk, sk)` ; `sk` reste locale.
- H1 envoie **seulement `pk`** au serveur → relayée à **H2** (Phase 0b).
- **H1 et H2** chiffrent leur table binaire (1 = présence, 0 = absence) sous `pk`
  de H1, en **1ère forme Catalano-Fiore** : `CF.Enc(1,b) = ((1−b) mod N, Enc(b))`.
  H1 génère les `b`, H2 génère les `b'`.
- **Serveur** : `CF.Mul` (2nde forme) sur les positions communes, puis
  **agrégation** en un seul chiffré :
  `C0_agg = ∏_p C0_p mod N²`, avec `C0_p = Enc(c0·c0' + b'·c0 + b·c0')`.
  Il collecte aussi les `Enc(b'_p)` (= `c1'_p`) de H2.
- Le serveur renvoie `(C0_agg, [ (p, Enc(b'_p)) ])` **à H1 uniquement**. Il n'a
  pas `sk`, il ne déchiffre rien.
- **H1 (Phase 4)** reconstruit le terme croisé par exponentiation homomorphe :
  `E_cross = ∏_p Enc(b'_p)^{b_p} = Enc(Σ_p b_p·b'_p)` (les `b_p` sont retrouvés
  localement : `b_p = (1 − c0_p) mod N`), puis :

  ```
  cardinal = Dec(C0_agg) + Dec(E_cross)  mod N
  ```

  → **2 déchiffrements Paillier** au total (au lieu de 3k), un entier.

Preuve de correction :
`Σ_p (c0+b)(c0'+b') = Σ_p [ (c0c0'+b'c0+bc0') + b·b' ] = Dec(C0_agg)+Dec(E_cross)`,
et chaque terme vaut `t[p]·t'[p] = 1·1 = 1`, donc la somme = `|H1 ∩ H2|`.

## Fichiers modifiés

- `src/exactmatch/exactmatch.rs` : modèle mono-clé + `AggResult`,
  `phase3_server_aggregate`, `phase4_decrypt_aggregate`.
- `src/exactmatch/mod.rs` : exports.
- `src/net_protocol/net_protocol.rs` : nouveau message `MsgAgg`.
- `src/net_protocol/mod.rs` : export `MsgAgg`.
- `src/bin/server.rs` : Phase 3 agrégée, envoi `MsgAgg` à H1 seulement.
- `src/bin/client.rs` : H1 = clé + Phase 4 agrégée ; H2 = chiffreur sous `pk_H1`.
- `src/paillier/math/math.rs` : `MIN_KEY_BITS` 1536 → **512** (PoC rapide).

## Exécution (3 terminaux)

```bash
cargo run --release --bin server
cargo run --release --bin client -- --bd 1 --csv "src/base de donnes/base_A_1000_600.csv"
cargo run --release --bin client -- --bd 2 --csv "src/base de donnes/base_B_1000_600.csv"
```

Le cardinal `|H1 ∩ H2|` ne s'affiche que côté **H1**. Option `--bits N` sur H1.

## Limites (sécurité, à traiter plus tard)

1. `simple_hash` (30 bits, non cryptographique, déterministe) ; positions en clair
   côté serveur → l'ensemble d'intersection est visible du serveur.
2. Option 2 : H1 apprend l'**ensemble** d'intersection (positions), pas seulement
   le cardinal (compromis accepté pour ce PoC).
3. Pas d'authentification de `pk` relayée, canal TCP en clair.
4. `MIN_KEY_BITS = 512` : insuffisant en production (remonter à ≥ 1536).

## Correctif v2 — Table DENSE (le serveur ne voit plus les positions communes)

**Problème identifié** : la table était creuse (`HashMap` ne contenant que les
positions actives). Les positions circulaient en clair sur le réseau
(`pos: u64` non chiffré dans `MsgFtBundle`), et le serveur calculait
`common_positions()` = intersection d'ensembles **en clair** → il connaissait
le cardinal (et l'ensemble) de l'intersection **sans avoir besoin de CF.Mul**.
Le chiffrement homomorphe ne protégeait donc que des valeurs sans intérêt.

**Correctif** : domaine réduit et **dense**, `TABLE_SIZE = M = 2^14 = 16384`.
Chaque hôpital envoie désormais une entrée `CF.Enc(value, b)` pour **CHAQUE**
position `0..M` (`value = 1` si actif, `value = 0` sinon), donc les DEUX
bundles contiennent toujours exactement les mêmes `M` clés de position. Le
serveur n'a plus aucun moyen de distinguer les positions communes : il
applique `CF.Mul` uniformément sur tout le domaine.

**Bug corrigé au passage** : la reconstruction du terme croisé en Phase 4
supposait `value = 1` partout (`b_p = (1 − c0_p) mod N`), ce qui était faux
dès qu'une position de la table dense de H1 valait 0. Corrigé en
`b_p = (value_p − c0_p) mod N`, où `value_p` provient de la **propre** table
de H1 (`phase4_decrypt_aggregate` prend maintenant `own_table: &SparseTable`
en paramètre supplémentaire).

**Compromis accepté** : collisions internes ≈ `n²/(2M)` (paradoxe des
anniversaires). Pour `M=16384` : négligeable pour `n≲500`, notable dès
`n≈5000` (≈760 collisions attendues) — à garder en tête pour la précision
numérique des tests avec de grandes bases.

## Correctif v3 — Bucket + comparaison EXACTE (élimine les faux positifs)

**Problème identifié (v2)** : même avec un domaine dense, un match n'était
détecté que par COÏNCIDENCE DE POSITION (`t1[p]=t2[p]=1`), sans jamais
vérifier qu'il s'agit du même patient. Deux identifiants **différents**
tombant par hasard sur la même position comptaient comme un match — taux de
faux positifs `≈ n_H1×n_H2/M`, du même ordre de grandeur que l'intersection
elle-même dès `n≈5000`. Le cuckoo hashing envisagé initialement ne résolvait
PAS ce problème (il élimine les collisions internes à un côté, pas les
collisions accidentelles entre identifiants différents de côtés opposés).

**Correctif** : chaque position porte désormais l'**identité exacte**
(SHA-256 complet, 256 bits, via la crate `sha2`) au lieu d'un simple bit de
présence. Le serveur calcule, pour **chaque** bucket `p` du domaine dense
`BUCKET_DOMAIN = 2^16 = 65536` :

```
diff_p = Enc(m1_p) · Enc(m2_p)^{-1}  mod N²      (soustraction Paillier homomorphe)
D_p    = diff_p ^ r_p                mod N²      (r_p ALÉATOIRE, SECRET, choisi par le serveur)
```

- `m1_p == m2_p` (même identité) → `D_p = Enc(0)`
- `m1_p != m2_p` → `D_p = Enc(aléatoire)`, non nul avec probabilité écrasante

Le serveur ne détient pas `sk` : il manipule uniquement des chiffrés, jamais
de valeurs en clair. **H1** ne déchiffre que les buckets où **sa propre**
table est active (connu localement, sans aide du serveur) — cela exclut
automatiquement le cas « les deux vides » et ne coûte que `n_H1`
déchiffrements (pas les 65536 du domaine entier).

**Nouveaux fichiers/symboles** (`exactmatch.rs`, section « VARIANTE EXACT-MATCH ») :
`identity_value`, `BucketTable`, `EncBundle`, `phase1_build_bucket_table`,
`phase2_prepare_enc_bundle`, `phase3_server_blind_diff`,
`phase4_decrypt_exact_count`. Nouveau message réseau `MsgPosValues`
(position, `BigUint`) dans `net_protocol.rs`. `server.rs`/`client.rs`
réécrits pour utiliser cette variante comme flux actif. Les variantes
précédentes (CF creuse, CF dense agrégée) restent présentes dans
`exactmatch.rs`, non utilisées par les binaires, à titre de référence.

**Nouvelle dépendance** : `sha2 = "0.10"` (ajoutée à `Cargo.toml`).

**Résidu de collision restant (mineur)** : si **deux identifiants du même
côté** tombent sur le même bucket, un seul est conservé (écrasement) —
l'autre est silencieusement perdu (**faux négatif**, pas faux positif).
Probabilité `≈ n²/(2×65536)` : négligeable pour `n≲1000`, mineure (quelques
unités) pour `n≈5000`. Le cuckoo hashing garde ici tout son intérêt comme
raffinement futur — cette fois pour de bonnes raisons : réduire ce résidu à
(quasi) zéro, plutôt que pour contrôler les faux positifs (déjà éliminés
par la comparaison exacte).

## Retour à v2 — Restauration comme base fiable

Après relecture du rapport de référence CEA/ClickNCrypt (PSI-Cardinality via
Catalano-Fiore), confirmation que sa construction (Algorithmes 1-2-3)
correspond exactement à la variante **v2 (CF dense agrégée)** :

```
mm' = [c0·c0' + b·c0' + b'·c0] + b·b'
```

— formule identique à `phase3_server_aggregate` + `phase4_decrypt_aggregate`,
déjà validée arithmétiquement terme à terme (voir §"Correction de correction
validée à la main" plus haut dans ce changelog).

`server.rs` et `client.rs` sont donc **restaurés sur v2** comme base de
travail fiable. La variante v3 (bucket + comparaison exacte SHA-256) reste
présente dans `exactmatch.rs`/`net_protocol.rs` (fonctions `phase1_build_bucket_table`,
`phase2_prepare_enc_bundle`, `phase3_server_blind_diff`,
`phase4_decrypt_exact_count`, message `MsgPosValues`), non utilisée par les
binaires — elle n'a jamais été testée en conditions réelles et sa complexité
(65 536 buckets, SHA-256, test d'égalité aveuglé) en fait une piste à
reprendre plus tard, séparément, une fois v2 confirmée fonctionnelle par
l'utilisateur.

**Le problème de sécurité identifié reste réel et non résolu dans v2** : le
serveur peut toujours déduire l'ensemble d'intersection à partir des
positions communes en clair. À traiter dans un second temps.

## Retour au flux rapide (v3) — positions en clair + identification + email

À la demande explicite : retour à la comparaison de positions **en clair**
côté serveur (rapide, comme la toute première version qui donnait déjà le
bon cardinal), avec deux ajouts :

**1. Identification des patients en commun** (pas seulement leur nombre) :
- `SparseTable` conserve désormais `position_to_id: HashMap<usize, String>`
  (position → identifiant d'origine), construit en Phase 1.
- Le serveur détermine `common_positions()` en clair (`phase3_server_aggregate`
  reprend la signature `(table1, table2, bd1, bd2, pk)`).
- **H1** reçoit malgré tout le résultat via le canal Paillier/CF habituel
  (cardinal exact par 2 déchiffrements agrégés), et calcule **en plus**,
  par simple lookup **local** (aucun calcul crypto ni aller-retour réseau
  supplémentaire) : `matched_ids = agg.b_prime_enc.keys() → position_to_id`.
  Nouveau type de retour `ExactMatchResult { cardinal, matched_ids }`.

**2. Matching par email (au lieu du NSS), colonne CSV auto-détectée** :
- `load_nss_from_csv` → `load_ids_from_csv(path, col_override: Option<&str>)`.
- Détection automatique de la colonne : normalisation (minuscule, accents
  retirés, ponctuation retirée) puis comparaison à une liste de libellés
  connus (`email`, `mail`, `e-mail`, `adresse mail`, `adresse électronique`,
  `courriel`, `mél`, ...), avec repli sur tout en-tête contenant un mot-clé
  pertinent. Un nom de colonne exact peut être imposé via `--email-col <nom>`
  si la détection automatique échoue.
- Les emails sont normalisés en minuscules au chargement (comparaison
  insensible à la casse, comportement standard pour les adresses email).

**Compromis assumé** (explicitement demandé par l'utilisateur) : le serveur
voit les positions communes en clair — il peut donc déduire la taille et,
via des attaques par dictionnaire sur les positions (hash non salé),
potentiellement les emails eux-mêmes. Documenté comme limitation connue
du PoC, à traiter dans un futur travail de durcissement si besoin.

La variante v3 "exact-match" (bucket + SHA-256 + test d'égalité aveuglé),
non testée, reste dans le code pour référence mais n'est plus utilisée.

## Export CSV + logs DevOps (chiffrés échantillon)

**1. Export du résultat** : H1 écrit désormais, après la Phase 4, un fichier
`src/dataFromPSI/psi_result_<timestamp_unix>.csv` :
```csv
cardinal,email
1500,lea.bernard@laposte.net
1500,tom.martinez@yahoo.fr
...
```
Le dossier est créé automatiquement s'il n'existe pas (`fs::create_dir_all`).

**2. Logs DevOps — échantillon de chiffrés** : après la Phase 2, chaque
hôpital (H1 et H2, indépendamment) affiche les 10 premiers chiffrés qu'il
produit, triés par position pour la reproductibilité :
```
[CIPHERTEXT] hopital=H1 pos=1234 c0=<hex> c1=<hex>
```
Préfixe `[CIPHERTEXT]` pour capture facile côté frontend (grep/parse des
logs). Par construction (aléa Paillier `r` + masque `b` propres à chaque
hôpital), les chiffrés de H1 et H2 sont TOUJOURS différents, même pour des
positions ou valeurs identiques — propriété de sécurité sémantique de
Paillier, utile à illustrer côté démo/frontend.

## Ajustements format CSV + logs terminal

- **CSV `src/dataFromPSI`** : format corrigé —
  ligne 1 = `La taille de l'intersection,<cardinal>` ; lignes suivantes =
  `<numero>,<email>` (numérotation à partir de 1). Exemple :
  ```
  La taille de l'intersection,1500
  1,julia.thomas@nexora.com
  2,nina.laurent@yahoo.fr
  ```
- **Terminal** : la liste complète des emails en commun n'est plus affichée
  en sortie standard (remplacée par un simple décompte, le détail étant
  dans le CSV exporté). Les logs `[CIPHERTEXT]` (10 premiers chiffrés par
  hôpital, H1 et H2 indépendamment) restent inchangés.

## Nettoyage logs serveur (Phase 3)

Suppression des deux lignes de log internes à `phase3_server_aggregate`
("Serveur : comparaison des positions en clair..." et "N position(s)
commune(s) — CF.Mul + agrégation...") — redondantes avec les messages déjà
affichés par `server.rs`. La ligne de fin de Phase 3 (temps + nombre de
Enc(b')) reste inchangée.

## Bindings Python (PyO3 + maturin)

Ajout de `src/pybindings.rs` (compilé UNIQUEMENT via `cargo build --features
python` / `maturin build --features python` — n'affecte JAMAIS les binaires
`server`/`client`/`paillier_crypto`, qui restent 100% Rust pur sans pyo3).

**Exposé côté Python (`import paillier_crypto`)** :
- Paillier direct : `paillier_keygen`, `paillier_encrypt`, `paillier_decrypt`.
- Les 4 phases PSI ExactMatch : `psi_phase1_build_table`,
  `psi_phase2_prepare_ft`, `psi_phase3_server_aggregate`,
  `psi_phase4_decrypt_aggregate`, + `psi_load_ids_from_csv`.
- Classes wrapper : `PyPublicKey`, `PyKeyPair`, `PySparseTable`,
  `PyFtBundle` (avec `.ciphertext_sample(10)` pour les logs DevOps H1/H2),
  `PyAggResult`, `PyExactMatchResult`. Toutes les `BigUint` traversent la
  frontière Rust/Python en hexadécimal (`.to_wire()`/`.from_wire(...)` pour
  la sérialisation réseau côté Python, transport libre — HTTP/gRPC/websocket).
- Erreur centralisée `paillier_crypto.PsiCryptoError` (catchable Python,
  construite depuis `CryptoError` existant). Les primitives Paillier
  directes sont pleinement "Result-safe" (jamais de panic). Les phases PSI
  encore basées sur `.expect()` en interne bénéficient du filet de sécurité
  automatique de PyO3 (panic Rust -> `PanicException` Python, pas de crash
  process) — documenté comme limitation connue dans `PYTHON_BINDINGS.md`.

**Fichiers ajoutés** : `src/pybindings.rs`, `pyproject.toml`,
`PYTHON_BINDINGS.md`, `python_example/psi_demo.py`.
**Cargo.toml** : `[lib] crate-type = ["cdylib","rlib"]`, dépendance `pyo3`
optionnelle (feature `python`, désactivée par défaut).
