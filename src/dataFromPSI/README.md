# src/dataFromPSI

Dossier de sortie des résultats du protocole PSI-ExactMatch.

À chaque exécution de `client --bd 1 ...`, H1 écrit ici un fichier
`psi_result_<timestamp_unix>.csv` contenant :

```csv
cardinal,email
1500,lea.bernard@laposte.net
1500,tom.martinez@yahoo.fr
...
```

- `cardinal` : le cardinal exact de l'intersection |H1 ∩ H2| (répété sur
  chaque ligne pour un CSV toujours directement exploitable).
- `email` : l'adresse email de chaque patient identifié comme commun aux
  deux bases (retrouvée localement par H1, sans calcul cryptographique
  supplémentaire — cf. `ExactMatchResult` dans `exactmatch.rs`).

Ce dossier est créé automatiquement par le programme s'il n'existe pas
encore (`fs::create_dir_all`).
