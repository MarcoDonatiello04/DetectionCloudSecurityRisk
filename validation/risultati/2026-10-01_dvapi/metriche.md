# Metriche di accuratezza — dvapi

| Categoria | Voci | VP | FN | Candidati | Fuori perimetro | Recall | Recall nel perimetro | Precisione minima |
|---|---|---|---|---|---|---|---|---|
| API1 | 1 | 0 | 0 | 0 | 1 | 0% | – | – |
| API2 | 1 | 0 | 0 | 0 | 1 | 0% | – | 0% |
| API3 | 1 | 0 | 1 | 0 | 0 | 0% | 0% | – |
| API4 | 1 | 0 | 1 | 0 | 0 | 0% | 0% | 0% |
| API5 | 1 | 0 | 1 | 0 | 0 | 0% | 0% | 0% |
| API6 | 1 | 0 | 0 | 0 | 1 | 0% | – | – |
| API7 | 1 | 0 | 1 | 0 | 0 | 0% | 0% | – |
| API8 | 1 | 0 | 1 | 0 | 0 | 0% | 0% | 0% |
| API9 | 1 | 1 | 0 | 0 | 0 | 100% | 100% | 3% |
| Totale | 9 | 1 | 5 | 0 | 3 | 11% | 17% | 2% |

## Voci

| Voce | Categoria | Punto | Esito | Come | Segnalazioni / motivo |
|---|---|---|---|---|---|
| D01 0xa1: Broken Object Level Authorization | API1 | GET /api/getNote | FUORI_PERIMETRO | decisione | Identificativo nella query (?username=), non modellato dal livello statico della BOLA; il livello dinamico non è partito perché i token di DVAPI riportano userId e non sub (limite noto, protocollo §7). |
| D02 0xa2: Broken Authentication | API2 | globale | FUORI_PERIMETRO | decisione | La Broken Authentication non è partita: cerca il manifest delle dipendenze nella radice del repository, DVAPI lo colloca in src/ (limite noto, protocollo §7). |
| D03 0xa3: Broken Object Property Level Authorization | API3 | POST /api/register | FN |  |  |
| D04 0xa4: Unrestricted Resource Consumption | API4 | POST /api/profile/upload | FN | decisione | Le candidate API4 sono il batching GraphQL (RC-004) e i limiti del container (RC-007); nessuna riguarda la dimensione del file caricato. |
| D05 0xa5: Broken Function Level Authorization | API5 | DELETE /api/user/{username} | FN | decisione | BF-005 segnala l'assenza di un diniego predefinito per l'intera applicazione, senza indicare l'endpoint DELETE /api/user/{username}: non identifica lo stesso punto di esposizione. |
| D06 0xa6: Server-Side Request Forgery | API7 | POST /api/addNoteWithLink | FN |  |  |
| D07 0xa7: Security Misconfiguration | API8 | GET /api/user/{username} | FN | decisione | Il riferimento accetta una segnalazione API8 di gestione degli errori verbosa a livello di applicazione; le candidate riguardano intestazioni, CORS e dipendenze, nessuna gli errori (SC-003). |
| D08 0xa8: Lack of Protection from Automated Threats | API6 | POST /api/addTicket | FUORI_PERIMETRO | decisione | Categoria principale API6, di logica di business e priva di modulo per costruzione; le candidate dell'alternativa API4 (RC-004, RC-007) non riguardano la frequenza delle richieste. |
| D09 0xa9: Improper Assets Management | API9 | POST /api/allChallenges | VP | percorso | spectral:owasp-api9-documented-endpoint:POST /api/allChallenges:72 |
| D10 0xa10: Unsafe Consumption of APIs | FUORI_TOP10 | POST /api/login | ESCLUSA |  | fuori dalla Top 10 API 2023 |

Segnalazioni in ambito: 44 — corrispondenti 1, vere non documentate 0, falsi positivi 0, da classificare 43.
