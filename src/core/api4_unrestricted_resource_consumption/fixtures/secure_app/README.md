# Secure App Fixture - API4:2023

Questo modulo conterrà la versione sicura dell'applicazione, protetta da **API4:2023 Unrestricted Resource Consumption**.

## Misure di Sicurezza da includere
- Limiti massimi fissati sulla paginazione.
- Restrizioni sulla dimensione massima dell'upload (Content-Length e controlli espliciti).
- Timeout specificati per ogni connessione esterna.
- Limitatori di profondità/complessità per GraphQL.
- Controlli di confine sui cicli.
- Rate limiting/Throttling per le integrazioni esterne.
