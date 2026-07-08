# Bindings Python (PyO3 + maturin)

## Build

```bash
pip install maturin
cd Paillier_v_mars
maturin develop --features python     # installe le module dans le venv actif (dev)
# ou, pour un wheel distribuable :
maturin build --release --features python
```

Le flag `--features python` est indispensable : sans lui, `pyo3` n'est même
pas compilé (les binaires `server`/`client`/`paillier_crypto` restent, eux,
100 % Rust pur, sans aucune dépendance à Python).

`pyproject.toml` déclare déjà `features = ["python"]` dans `[tool.maturin]`,
donc un simple `maturin develop` (sans `--features`) suffit normalement —
le flag explicite ci-dessus est là en cas de doute/débogage.

## Ce qui est exposé (`import paillier_crypto`)

### Paillier — primitives directes
- `paillier_keygen(bits: int) -> PyKeyPair`
- `paillier_encrypt(m_hex: str, pk: PyPublicKey) -> str`
- `paillier_decrypt(c_hex: str, kp: PyKeyPair) -> str`

Toutes les valeurs (`n`, `g`, `n_squared`, messages, chiffrés) traversent la
frontière Rust/Python sous forme de **chaînes hexadécimales** — convertibles
côté Python via `int(x, 16)` si besoin d'un entier natif.

### PSI ExactMatch — les 4 phases
- `psi_load_ids_from_csv(path: str, col_override: str | None = None) -> list[str]`
- `psi_phase1_build_table(label: str, ids: list[str]) -> PySparseTable`
- `psi_phase2_prepare_ft(label: str, table: PySparseTable, pk: PyPublicKey) -> PyFtBundle`
- `psi_phase3_server_aggregate(table1, table2, bd1: PyFtBundle, bd2: PyFtBundle, pk: PyPublicKey) -> PyAggResult`
- `psi_phase4_decrypt_aggregate(label, agg: PyAggResult, own_bundle: PyFtBundle, own_table: PySparseTable, kp: PyKeyPair) -> PyExactMatchResult`

### Classes utilitaires
- `PyPublicKey` : `.n`, `.g`, `.n_squared` (hex), `.bits`
- `PyKeyPair` : `.public_key -> PyPublicKey`, `.secret_key_hex()` (⚠️ sensible)
- `PySparseTable` : `.len()`, `.active_positions()`
- `PyFtBundle` : `.len()`, `.ciphertext_sample(n)`, `.to_wire()`, `.from_wire(entries)` (statique)
- `PyAggResult` : `.to_wire()`, `.from_wire(c0_agg_hex, entries)` (statique)
- `PyExactMatchResult` : `.cardinal`, `.matched_ids`

Les méthodes `.to_wire()` / `.from_wire(...)` servent à sérialiser les objets
pour votre transport réseau (HTTP/gRPC/websocket/etc.) — ces bindings ne
prennent aucune décision de transport, ils exposent uniquement le calcul.

## Erreurs centralisées : `paillier_crypto.PsiCryptoError`

Toute erreur crypto structurée (message hors domaine, clé trop petite,
chiffré invalide, inverse modulaire inexistant, CSV introuvable, colonne
email non détectée...) est levée comme une exception Python normale et
catchable :

```python
try:
    kp = paillier_crypto.paillier_keygen(10)   # trop petit
except paillier_crypto.PsiCryptoError as e:
    print(f"Erreur : {e}")   # le process Python NE CRASHE PAS
```

**Note de robustesse** : PyO3 intercepte *automatiquement* tout panic Rust
survenant dans une fonction exposée et le convertit en exception Python
(`pyo3_runtime.PanicException`) au lieu de faire planter l'interpréteur.
Cette protection s'applique donc aussi aux chemins internes du protocole PSI
qui utilisent encore `.expect()` en interne (pas encore tous convertis en
`Result<_, CryptoError>` à ce jour — piste d'amélioration continue si vous
voulez remonter des messages d'erreur plus fins que "panic" pour ces cas
précis). Les primitives Paillier directes (`paillier_keygen/encrypt/decrypt`)
sont, elles, déjà pleinement "Result-safe" : elles lèvent systématiquement
`PsiCryptoError` avec un message clair, jamais de panic.

## Exemple complet

Voir `python_example/psi_demo.py` — orchestre les 4 phases en un seul
process à des fins de démonstration (H1, H2 et le calcul serveur), affiche
les 10 premiers chiffrés de chaque hôpital (log `[CIPHERTEXT]`, identique au
format des binaires Rust), et exporte le résultat au même format CSV que la
version binaire (`src/dataFromPSI/psi_result_<timestamp>.csv`).
