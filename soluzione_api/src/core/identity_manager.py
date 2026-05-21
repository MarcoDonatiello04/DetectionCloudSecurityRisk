import os
import requests
from typing import Dict, Any

class KeycloakIdentityManager:
    """
    Identity Manager del Framework di API Security Posture Management.
    Automatizza l'ottenimento dei token JWT reali da Keycloak usando il flusso
    OAuth2 "Resource Owner Password Credentials" per preparare le sessioni di test DAST.
    """
    def __init__(self, keycloak_url: str = None, realm: str = "myrealm", client_id: str = "api-client"):
        # Se non specificato, usiamo localhost:8080 (URL di Keycloak esposto sull'host per i test client)
        self.keycloak_url = (keycloak_url or os.environ.get("KEYCLOAK_URL", "http://localhost:8080")).rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.token_endpoint = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"

    def fetch_jwt_token(self, username: str, password: str) -> str:
        """
        Esegue una richiesta POST all'endpoint OpenID Connect Token di Keycloak
        per ottenere un JWT valido usando il flusso Password Credentials.
        """
        payload = {
            "client_id": self.client_id,
            "grant_type": "password",
            "username": username,
            "password": password
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = requests.post(
                self.token_endpoint, 
                data=payload, 
                headers=headers, 
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                access_token = data.get("access_token")
                if access_token:
                    return access_token
                else:
                    print(f"⚠️ Warning: Risposta Keycloak per {username} priva di access_token.")
            else:
                print(f"❌ Errore autenticazione Keycloak per {username} (Stato: {response.status_code}): {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"🔴 Impossibile connettersi a Keycloak all'endpoint {self.token_endpoint}: {e}")
            
        return None

    def get_test_sessions(self) -> Dict[str, Dict[str, str]]:
        """
        Esegue il login per gli utenti di test specificati e restituisce un dizionario
        contenente gli header di autorizzazione già pronti per essere passati
        a client HTTP (come requests o il proxy ZAP).
        
        Struttura del dizionario restituito:
        {
            "userA": {"Authorization": "Bearer <JWT_USER_A>"},
            "userB": {"Authorization": "Bearer <JWT_USER_B>"},
            "admin": {"Authorization": "Bearer <JWT_ADMIN>"},
            "anonymous": {}
        }
        """
        credentials = {
            "userA": ("user_a", "Password123!"),
            "userB": ("user_b", "Password123!"),
            "admin": ("admin_user", "SuperSecretAdmin1!")
        }
        
        sessions = {}
        
        for session_name, (username, password) in credentials.items():
            token = self.fetch_jwt_token(username, password)
            if token:
                sessions[session_name] = {
                    "Authorization": f"Bearer {token}"
                }
            else:
                sessions[session_name] = {
                    "Authorization": "Bearer TOKEN_ACQUISITION_FAILED"
                }
                print(f"⚠️ Generata sessione fallimentare fittizia per {session_name}.")

        # Aggiunta sessione anonima per testare accessi non autenticati
        sessions["anonymous"] = {}
        
        return sessions

# Esecuzione standalone per diagnostica locale ed ispezione dei token generati
if __name__ == "__main__":
    print("="*80)
    print("🧪 Keycloak Identity Manager - Test Standalone")
    print("="*80)
    
    manager = KeycloakIdentityManager()
    print(f"Configurato Keycloak Token Endpoint: {manager.token_endpoint}")
    print("Richiesta sessioni di autenticazione in corso...")
    
    sessions = manager.get_test_sessions()
    
    for user_key, header in sessions.items():
        if "Authorization" in header:
            token_preview = header["Authorization"][:40] + "..." if len(header["Authorization"]) > 40 else header["Authorization"]
            print(f"🟢 Sessione per '{user_key}': {token_preview}")
        else:
            print(f"⚪ Sessione per '{user_key}': Nessun header di autorizzazione (Anonima)")
            
    print("="*80)
