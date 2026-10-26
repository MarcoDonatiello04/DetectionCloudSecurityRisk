# Metriche di accuratezza — vampi_sicuro

| Categoria | Voci | VP | FN | Candidati | Fuori perimetro | Recall | Recall nel perimetro | Precisione minima |
|---|---|---|---|---|---|---|---|---|
| API1 | 2 | 0 | 1 | 0 | 1 | 0% | 0% | 0% |
| API2 | 2 | 1 | 0 | 0 | 1 | 50% | 100% | 11% |
| API3 | 2 | 0 | 2 | 0 | 0 | 0% | 0% | – |
| API4 | 2 | 0 | 1 | 0 | 1 | 0% | 0% | 0% |
| Totale | 8 | 1 | 4 | 0 | 3 | 12% | 20% | 6% |

## Voci

| Voce | Categoria | Punto | Esito | Come | Segnalazioni / motivo |
|---|---|---|---|---|---|
| V01 SQLi Injection | FUORI_TOP10 | GET /users/v1/{username} | ESCLUSA |  | fuori dalla Top 10 API 2023 |
| V02 Unauthorized Password Change | API1 | PUT /users/v1/{username}/password | FUORI_PERIMETRO | decisione | PUT su un oggetto altrui: sui bersagli esterni il livello dinamico prova solo i metodi che non modificano i dati (nessun ripristino dello stato); il livello statico della BOLA non risolve le rotte dichiarate nel contratto da connexion. |
| V03 Broken Object Level Authorization | API1 | GET /books/v1/{book} | FN |  |  |
| V04 Mass Assignment | API3 | POST /users/v1/register | FN |  |  |
| V05 Excessive Data Exposure through debug endpoint | API3 | GET /users/v1/_debug | FN | decisione | Le candidate API8 descrivono la modalità di debug di Flask (SC-002), le intestazioni, CORS e le dipendenze; nessuna segnala l'endpoint di debug che espone gli utenti. |
| V06 User and Password Enumeration | API2 | POST /users/v1/login | VP | percorso | spectral:owasp-api2-operation-security:POST /users/v1/login:335 |
| V07 RegexDOS (Denial of Service) | API4 | PUT /users/v1/{username}/email | FUORI_PERIMETRO | decisione | Il modulo dell'Unrestricted Resource Consumption non ha regole per il ReDoS. |
| V08 Lack of Resources & Rate Limiting | API4 | globale | FN | decisione | Le candidate API4 riguardano i limiti di risorse del container (RC-007) e la dimensione del corpo (RC-008), non la frequenza delle richieste. L'assenza di limiti di frequenza è rilevata dalla prova T03 della Broken Authentication, ma come API2: la regola chiede la stessa categoria. |
| V09 JWT authentication bypass via weak signing key | API2 | globale | FUORI_PERIMETRO | decisione | Nessuna prova della Broken Authentication tenta di ricavare il segreto di firma del JWT con un dizionario. |

Segnalazioni in ambito: 17 — corrispondenti 1, vere non documentate 0, falsi positivi 0, da classificare 16.
