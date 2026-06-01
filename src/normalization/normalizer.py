import re
from typing import List, Dict, Any


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
    HEX_HASH_REGEX = re.compile(r'^[a-fA-F0-9]{8,64}$')

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
        
        # Rimuove il prefisso delle API Gateway di LocalStack se presente
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

            if segment.startswith('{') and segment.endswith('}'):
                normalized_segments.append(segment)
                continue

            if cls.UUID_REGEX.match(segment):
                normalized_segments.append("{id}")
            elif cls.NUMERIC_REGEX.match(segment):
                normalized_segments.append("{id}")
            elif cls.HEX_HASH_REGEX.match(segment):
                if segment.lower() not in ("login", "admin", "debug", "notes", "users", "items", "views", "posts", "lists"):
                    normalized_segments.append("{id}")
                else:
                    normalized_segments.append(segment)
            else:
                normalized_segments.append(segment)

        normalized_path = "/".join(normalized_segments)
        normalized_path = re.sub(r'//+', '/', normalized_path)
        
        if not normalized_path.startswith('/'):
            normalized_path = '/' + normalized_path
            
        return normalized_path
