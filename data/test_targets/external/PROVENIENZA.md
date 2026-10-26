# Bersagli esterni — provenienza

Bersagli scritti da terzi, usati SOLO per la validazione dello strumento (insieme di prova).
Non vanno usati per sviluppare o correggere regole: un bersaglio usato per correggere lo
strumento passa all'insieme di sviluppo e i suoi risultati non valgono più come validazione.

Copie dei repository alla revisione indicata, ottenute con `git archive` (senza cronologia git).

| Bersaglio | Repository | Commit | Data commit | Scaricato il |
|---|---|---|---|---|
| vampi | https://github.com/erev0s/VAmPI | f16052dce83f05847133ec98f01c5193a41de7d8 | 2026-04-07 | 2026-10-01 |
| dvapi | https://github.com/payatu/DVAPI | bde30d295aa8bc7f5516396fbae19d9630c11600 | 2025-09-22 | 2026-10-01 |
| sadcloud | https://github.com/nccgroup/sadcloud | f538652921a7f3e8e25c0afaecad2d4382f8b21e | 2021-07-09 | 2026-10-01 |

## Modifiche rispetto all'originale

- `sadcloud/sadcloud/terraform.tfvars`: `all_findings = false` → `all_findings = true`,
  come indicato dal README per attivare tutte le misconfiguration. Nessun'altra modifica.
- vampi, dvapi: nessuna modifica.

Riferimenti di verità: `validation/ground_truth/`. Protocollo: `validation/PROTOCOLLO.md`.
