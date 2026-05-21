import re
from typing import List, Dict, Any, Set

class APIEndpointNormalizer:
    """
    Normalizzatore euristico avanzato per rotte API.
    Converte segmenti dinamici del path (numeri, UUID, hash hex) in token generici
    OpenAPI-compliant (es. {id}), permettendo l'aggregazione, la deduplicazione
    e la correlazione tra endpoint statici e dinamici intercettati a runtime.
    """
    
    # Regex Patterns per identificare segmenti dinamici
    UUID_REGEX = re.compile(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')
    NUMERIC_REGEX = re.compile(r'^\d+$')
    HEX_HASH_REGEX = re.compile(r'^[a-fA-F0-9]{8,64}$') # Stringhe hex (MD5, SHA1/256 o identificativi generati)

    @classmethod
    def normalize_path(cls, path: str) -> str:
        """
        Normalizza un percorso URL trasformando i segmenti dinamici in '{id}'.
        Esempio: /api/v1/users/123/profile?debug=true -> /api/v1/users/{id}/profile
        """
        if not path:
            return "/"
            
        # Rimuove query parameters se presenti
        path = path.split('?')[0]
        
        # Rimuove il prefisso delle API Gateway di LocalStack se presente (es. /restapis/0uuofdetq8/dev/_user_request_)
        path = re.sub(r'^/restapis/[a-zA-Z0-9]+/[^/]+/_user_request_', '', path)
        
        # Rimuove slash finale ridondante se non è il path root
        if path.endswith('/') and path != '/':
            path = path.rstrip('/')

        segments = path.split('/')
        normalized_segments = []

        for segment in segments:
            if not segment:
                normalized_segments.append("")
                continue

            # Se il segmento è già formattato come parametro OpenAPI (es. {id}), mantienilo
            if segment.startswith('{') and segment.endswith('}'):
                normalized_segments.append(segment)
                continue

            # Controlla se corrisponde ad un UUID
            if cls.UUID_REGEX.match(segment):
                normalized_segments.append("{id}")
            # Controlla se corrisponde ad un numero
            elif cls.NUMERIC_REGEX.match(segment):
                normalized_segments.append("{id}")
            # Controlla se corrisponde ad un hash esadecimale (es: identificatori MongoDB o sessioni)
            elif cls.HEX_HASH_REGEX.match(segment):
                # Escludiamo parole note corte per evitare falsi positivi
                if segment.lower() not in ("login", "admin", "debug", "notes", "users", "notes", "items", "views", "posts", "lists"):
                    normalized_segments.append("{id}")
                else:
                    normalized_segments.append(segment)
            else:
                normalized_segments.append(segment)

        normalized_path = "/".join(normalized_segments)
        
        # Riconduciamo slash doppi a slash singolo
        normalized_path = re.sub(r'//+', '/', normalized_path)
        
        if not normalized_path.startswith('/'):
            normalized_path = '/' + normalized_path
            
        return normalized_path

    @classmethod
    def deduplicate_and_normalize(cls, raw_endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalizza e raggruppa una lista di endpoint grezzi,
        preservando i metadata cumulativi (sorgenti, metodi, parametri).
        """
        unique_endpoints: Dict[str, Dict[str, Any]] = {}

        for ep in raw_endpoints:
            raw_path = ep.get("path", "")
            method = ep.get("method", "GET").upper()
            source = ep.get("source", "static")
            
            # Filtro anti-rumore DAST: Escludiamo i probe di scansione di OWASP ZAP 
            # e i file di sistema/configurazione scansionati dai crawler
            path_lower = raw_path.lower()
            if "zap" in path_lower or any(p in path_lower for p in (
                "robots.txt", "sitemap.xml", "favicon.ico", "web-inf", "meta-inf", 
                ".git", ".env", ".htaccess", "wp-login.php", "phpmyadmin"
            )):
                continue
            
            norm_path = cls.normalize_path(raw_path)
            key = f"{method}:{norm_path}"

            if key not in unique_endpoints:
                unique_endpoints[key] = {
                    "path": norm_path,
                    "methods": {method},
                    "sources": {source},
                    "auth_detected": ep.get("auth_detected", False),
                    "framework": ep.get("framework", "unknown"),
                    "file": ep.get("file", ""),
                    "query_params": set(ep.get("query_params", {}).keys()) if "query_params" in ep else set(),
                    "body_params": set(ep.get("body_params", {}).keys()) if "body_params" in ep else set(),
                    "status_codes": {ep.get("status")} if "status" in ep else set()
                }
            else:
                entry = unique_endpoints[key]
                entry["methods"].add(method)
                entry["sources"].add(source)
                if ep.get("auth_detected"):
                    entry["auth_detected"] = True
                if ep.get("framework") and ep.get("framework") != "unknown":
                    entry["framework"] = ep.get("framework")
                if ep.get("file") and not entry["file"]:
                    entry["file"] = ep.get("file")
                if "query_params" in ep:
                    entry["query_params"].update(ep["query_params"].keys())
                if "body_params" in ep:
                    entry["body_params"].update(ep["body_params"].keys())
                if "status" in ep:
                    entry["status_codes"].add(ep["status"])

        # Convertiamo i set in liste per l'output serializzabile JSON
        result = []
        for entry in unique_endpoints.values():
            result.append({
                "path": entry["path"],
                "methods": list(entry["methods"]),
                "sources": list(entry["sources"]),
                "auth_detected": entry["auth_detected"],
                "framework": entry["framework"],
                "file": entry["file"],
                "query_params": list(entry["query_params"]),
                "body_params": list(entry["body_params"]),
                "status_codes": list(filter(None, entry["status_codes"]))
            })

        return result

if __name__ == "__main__":
    test_paths = [
        "/api/users/123",
        "/api/users/456/profile",
        "/orders/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        "/documents/3a2f8c9b",
        "/login?q=test"
    ]
    for p in test_paths:
        print(f"{p} ➡️ {APIEndpointNormalizer.normalize_path(p)}")
