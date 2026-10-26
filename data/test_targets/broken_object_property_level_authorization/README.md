# Applicazioni gemelle BOPLA (OWASP API3:2023)

Coppia usata per la validazione del modulo `src/core/api3_bopla` (test:
`tests/integration/api3_bopla/test_bopla_ground_truth.py`).

- `vulnerable_app/app.py`: il profilo utente espone `salary` e `role` a chiunque lo legga e
  l'aggiornamento assegna ogni campo ricevuto (mass assignment).
- `secure_app/app.py`: stessa struttura; `salary` e `role` sono visibili e modificabili solo
  dall'amministratore. I campi non ammessi vengono ignorati con risposta 200, così la
  validazione verifica che il modulo non si fidi del solo codice di stato.
- `openapi.json`: contratto comune, che documenta solo `id`, `name`, `email`.
- `client_traffic.json`: traffico comune di un utente ordinario (il client invia anche `role`
  nel modulo di profilo, un campo non documentato).

Le app non usano un framework web: espongono `handle(method, path, headers, body)` e
vengono interrogate nello stesso processo dei test. Identità: `alice` (utente ordinario) e
`admin`, riconosciute dal claim `sub` di un token JWT non firmato.

Riferimento di verità: sulla variante vulnerabile ciascuna prova T01–T07 conferma la propria
condizione; sulla variante sicura nessuna segnalazione è confermata e il punteggio resta 100.
