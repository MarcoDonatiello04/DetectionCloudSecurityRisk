# Vulnerable App Fixture - API4:2023

Questo modulo conterrà un'applicazione Flask/FastAPI volutamente vulnerabile a **API4:2023 Unrestricted Resource Consumption**.

## Scenari di Vulnerabilità da includere
- Paginazione non limitata.
- Upload file senza limiti dimensionali.
- Chiamate esterne senza timeout.
- GraphQL batching illimitato.
- Cicli guidati dall'input utente senza bound rigidi.
- Chiamate a servizi terzi costosi non regolate (assenza di rate limiting/throttling).
