import json
import os
import yaml
from typing import List, Dict, Any

class OpenAPISpecGenerator:
    """
    Generatore automatico di contratti OpenAPI 3.0.0 basati sulla
    Unified API Inventory deduplicata e normalizzata.
    Produce file standard sia in formato JSON che YAML.
    """
    
    def __init__(self, unified_inventory: List[Dict[str, Any]], base_url: str = "http://localhost:5000"):
        self.unified_inventory = unified_inventory
        self.base_url = base_url

    def build_spec(self) -> Dict[str, Any]:
        """Costruisce il dizionario strutturato conforme allo standard OpenAPI 3.0.0."""
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Unified Runtime API Specification",
                "description": "Contratto OpenAPI autogenerato dinamicamente tramite la pipeline di API Discovery statica/dinamica e traffic extraction.",
                "version": "1.0.0"
            },
            "servers": [
                {
                    "url": self.base_url,
                    "description": "Live Environment di Rilevamento"
                }
            ],
            "paths": {}
        }

        # Organizza gli endpoint per path
        paths_dict = spec["paths"]
        
        for ep in self.unified_inventory:
            path = ep.get("path", "")
            method = ep.get("method", "GET").lower()
            classification = ep.get("classification", "STATIC_ONLY")
            auth_detected = ep.get("auth_detected", False)
            
            if path not in paths_dict:
                paths_dict[path] = {}

            # Estrazione parametri di path
            path_params = []
            # Se il path contiene parametri es. {id}
            segments = path.split('/')
            for segment in segments:
                if segment.startswith('{') and segment.endswith('}'):
                    param_name = segment.strip('{}')
                    path_params.append({
                        "name": param_name,
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string"
                        },
                        "description": f"Parametro di path '{param_name}' estratto euristica"
                    })

            # Costruiamo il blocco dell'operazione
            operation = {
                "summary": f"Endpoint {method.upper()} per {path}",
                "description": f"Rilevato tramite pipeline (Classificazione: {classification}, Confidence: {ep.get('confidence_score')}).",
                "responses": {}
            }

            # Se ci sono parametri di path rilevati
            if path_params:
                operation["parameters"] = path_params

            # Aggiungiamo i query parameters rilevati a runtime
            if ep.get("query_params"):
                if "parameters" not in operation:
                    operation["parameters"] = []
                for q_p in ep["query_params"]:
                    operation["parameters"].append({
                        "name": q_p,
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "string"
                        },
                        "description": "Parametro query osservato a runtime"
                    })

            # Se è richiesta autenticazione
            if auth_detected:
                operation["security"] = [{"bearerAuth": []}]
                
                # Definiamo il Security Schemes in components se c'è auth
                if "components" not in spec:
                    spec["components"] = {
                        "securitySchemes": {
                            "bearerAuth": {
                                "type": "http",
                                "scheme": "bearer",
                                "bearerFormat": "JWT"
                            }
                        }
                    }

            # Aggiungiamo i codici di risposta osservati o quelli standard
            status_codes = ep.get("observed_status_codes", [])
            if status_codes:
                for status in status_codes:
                    operation["responses"][str(status)] = {
                        "description": f"Risposta osservata con status {status}"
                    }
            else:
                # Default fallback
                operation["responses"]["200"] = {
                    "description": "Operazione completata con successo"
                }

            # Inseriamo l'operazione nel path corrispondente
            paths_dict[path][method] = operation

        return spec

    def save_specifications(self, output_dir: str):
        """Salva le specifiche in formato JSON e YAML nella directory indicata."""
        os.makedirs(output_dir, exist_ok=True)
        spec = self.build_spec()

        json_path = os.path.join(output_dir, "openapi_runtime.json")
        yaml_path = os.path.join(output_dir, "openapi_runtime.yaml")

        # Scrittura JSON
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)

        # Scrittura YAML (con PyYAML)
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(spec, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        print(f"📄 OpenAPI Spec salvata correttamente:")
        print(f" - JSON: {json_path}")
        print(f" - YAML: {yaml_path}")

    def enrich_existing_spec(self, existing_spec_path: str):
        """
        Carica un file OpenAPI esistente (YAML o JSON) e inietta gli endpoint
        rilevati dalla pipeline che non sono ancora documentati.
        """
        if not os.path.exists(existing_spec_path):
            print(f"⚠️ Spec esistente '{existing_spec_path}' non trovata. Impossibile arricchirla.")
            return

        print(f"🔄 Arricchimento del file OpenAPI esistente: {existing_spec_path}")
        
        # Carica il formato appropriato
        is_yaml = existing_spec_path.endswith(('.yaml', '.yml'))
        try:
            with open(existing_spec_path, 'r', encoding='utf-8') as f:
                if is_yaml:
                    spec = yaml.safe_load(f) or {}
                else:
                    spec = json.load(f) or {}
        except Exception as e:
            print(f"❌ Errore nel caricamento del file OpenAPI esistente: {e}")
            return

        if "paths" not in spec:
            spec["paths"] = {}

        paths_dict = spec["paths"]
        added_count = 0

        for ep in self.unified_inventory:
            path = ep.get("path", "")
            method = ep.get("method", "GET").lower()
            classification = ep.get("classification", "STATIC_ONLY")
            auth_detected = ep.get("auth_detected", False)

            # Verifica se l'endpoint (path + metodo) è già documentato
            if path in paths_dict and method in paths_dict[path]:
                continue  # Già presente, lo saltiamo per non sovrascrivere dettagli esistenti

            # Altrimenti è NON DOCUMENTATO! Lo aggiungiamo
            if path not in paths_dict:
                paths_dict[path] = {}

            # Estrazione parametri di path
            path_params = []
            segments = path.split('/')
            for segment in segments:
                if segment.startswith('{') and segment.endswith('}'):
                    param_name = segment.strip('{}')
                    path_params.append({
                        "name": param_name,
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string"
                        },
                        "description": f"Parametro di path '{param_name}' rilevato a runtime"
                    })

            operation = {
                "summary": f"Endpoint {method.upper()} rilevato (Non Documentato)",
                "description": f"Rilevato a runtime (Classificazione: {classification}, Confidence: {ep.get('confidence_score')}).",
                "responses": {}
            }

            if path_params:
                operation["parameters"] = path_params

            if ep.get("query_params"):
                if "parameters" not in operation:
                    operation["parameters"] = []
                for q_p in ep["query_params"]:
                    operation["parameters"].append({
                        "name": q_p,
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "string"
                        },
                        "description": "Parametro query osservato a runtime"
                    })

            if auth_detected:
                operation["security"] = [{"bearerAuth": []}]
                
                # Assicuriamoci che bearerAuth sia definita
                if "components" not in spec:
                    spec["components"] = {}
                if "securitySchemes" not in spec["components"]:
                    spec["components"]["securitySchemes"] = {}
                if "bearerAuth" not in spec["components"]["securitySchemes"]:
                    spec["components"]["securitySchemes"]["bearerAuth"] = {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }

            status_codes = ep.get("observed_status_codes", [])
            if status_codes:
                for status in status_codes:
                    operation["responses"][str(status)] = {
                        "description": f"Risposta osservata con status {status}"
                    }
            else:
                operation["responses"]["200"] = {
                    "description": "Operazione completata con successo"
                }

            paths_dict[path][method] = operation
            added_count += 1
            print(f" ✨ Aggiunto endpoint non documentato: {method.upper()} {path}")

        if added_count > 0:
            # Salva nuovamente il file arricchito nello stesso formato
            try:
                with open(existing_spec_path, 'w', encoding='utf-8') as f:
                    if is_yaml:
                        yaml.dump(spec, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                    else:
                        json.dump(spec, f, indent=2, ensure_ascii=False)
                print(f"✅ File OpenAPI esistente aggiornato con successo! Aggiunti {added_count} nuovi endpoint.")
            except Exception as e:
                print(f"❌ Errore durante il salvataggio del file OpenAPI aggiornato: {e}")
        else:
            print("ℹ️ Tutti gli endpoint rilevati sono già documentati nel file OpenAPI esistente.")
