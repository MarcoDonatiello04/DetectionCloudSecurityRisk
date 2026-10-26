"""
Genera il traffico di ESERCIZIO di un bersaglio esterno attraverso mitmproxy.

Serve alla BOLA dinamica in Assessment Mode sui bersagli non cooperanti (VAmPI, DVAPI):
due utenti si registrano, accedono e usano SOLO i propri oggetti, come farebbe un utente
normale. Nessuna richiesta d'attacco: gli attacchi li genera lo strumento, dopo, a partire
da questo traffico. Le operazioni sono ricavate dalla documentazione degli autori
(tabella del README di VAmPI, collezione Postman di DVAPI), non dal codice.

Uso (dalla radice del progetto, con mitmproxy e il bersaglio attivi):
    PYTHONPATH=. .venv/bin/python entrypoints/operations/genera_traffico_esercizio.py vampi
    PYTHONPATH=. .venv/bin/python entrypoints/operations/genera_traffico_esercizio.py vampi_sicuro
    PYTHONPATH=. .venv/bin/python entrypoints/operations/genera_traffico_esercizio.py dvapi

Il traffico catturato viene copiato in output/external/<bersaglio>/raw_traffic.json, la
cartella che la dashboard di quel bersaglio legge (make dashboard-<bersaglio>).
"""

import json
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

PROXY = {"http": "http://localhost:8081", "https": "http://localhost:8081"}
# Il proxy gira in un container: per lui "localhost" e' il container stesso, quindi il
# bersaglio (sull'host) va indicato come host.docker.internal.
HOSTS = {
    "vampi": "http://host.docker.internal:5002",
    "vampi_sicuro": "http://host.docker.internal:5001",
    "dvapi": "http://host.docker.internal:3000",
}
USERS = [("tesi_victim", "Tesi-Victim-2026!"), ("tesi_peer", "Tesi-Peer-2026!")]
CAPTURE = Path("output/raw_traffic.json")


def _token_from(res: requests.Response) -> str | None:
    auth = res.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1]
    try:
        body = res.json()
    except ValueError:
        return None
    for key in ("auth_token", "token", "access_token", "accessToken", "jwt"):
        if isinstance(body, dict) and body.get(key):
            return body[key]
    return None


def _call(method: str, url: str, token: str | None = None, **kw) -> requests.Response:
    headers = kw.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    res = requests.request(method, url, headers=headers, proxies=PROXY, timeout=15, **kw)
    print(f"  {method:6} {url.split('//', 1)[1]:55} -> {res.status_code}")
    return res


def esercizio_vampi(base: str) -> None:
    _call("GET", f"{base}/createdb")
    for username, password in USERS:
        _call(
            "POST",
            f"{base}/users/v1/register",
            json={"username": username, "password": password, "email": f"{username}@tesi.local"},
        )
        token = _token_from(
            _call(
                "POST", f"{base}/users/v1/login", json={"username": username, "password": password}
            )
        )
        if not token:
            print(f"  [!] nessun token per {username}: controlla il bersaglio")
            continue
        title = f"libro_di_{username}"
        _call("GET", f"{base}/me", token)
        _call("GET", f"{base}/users/v1/{username}", token)
        _call(
            "POST",
            f"{base}/books/v1",
            token,
            json={"book_title": title, "secret": f"segreto di {username}"},
        )
        _call("GET", f"{base}/books/v1/{title}", token)


def esercizio_dvapi(base: str) -> None:
    for username, password in USERS:
        _call("POST", f"{base}/api/register", json={"username": username, "password": password})
        token = _token_from(
            _call("POST", f"{base}/api/login", json={"username": username, "password": password})
        )
        if not token:
            print(f"  [!] nessun token per {username}: controlla il bersaglio")
            continue
        _call("GET", f"{base}/api/profile", token)
        _call("GET", f"{base}/api/user/{username}", token)
        _call("POST", f"{base}/api/addNote", token, json={"note": f"nota di {username}"})
        _call("GET", f"{base}/api/getNote", token, params={"username": username})
        _call("GET", f"{base}/api/getSolves", token)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in HOSTS:
        print(f"Uso: {sys.argv[0]} {{{'|'.join(HOSTS)}}}")
        return 2
    target = sys.argv[1]
    base = HOSTS[target]

    # mitmproxy ricarica e riscrive tutto il file a ogni risposta: per non mescolare il
    # traffico di bersagli diversi si archivia la cattura precedente e si riavvia il proxy.
    archived = None
    if CAPTURE.exists():
        archived = CAPTURE.with_name(f"raw_traffic.{datetime.now():%Y%m%d_%H%M%S}.json")
        CAPTURE.rename(archived)
        print(f"[i] Cattura precedente archiviata in {archived}")
    print("[i] Riavvio di mitmproxy con una cattura vuota...")
    subprocess.run(["docker", "compose", "restart", "mitmproxy"], check=True)
    time.sleep(3)

    print(f"[+] Traffico di esercizio verso {target} ({base}) tramite mitmproxy:")
    (esercizio_vampi if target.startswith("vampi") else esercizio_dvapi)(base)
    time.sleep(1)

    if not CAPTURE.exists():
        print("[-] Nessun traffico catturato: mitmproxy e' attivo sulla porta 8081?")
        return 1
    dest = Path("output/external") / target / "raw_traffic.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CAPTURE, dest)
    entries = len(json.loads(CAPTURE.read_text(encoding="utf-8")))
    print(f"[+] {entries} richieste catturate e copiate in {dest}")

    # output/raw_traffic.json è anche il traffico letto dalla dashboard principale (bersaglio
    # interno): lasciarci il traffico del bersaglio esterno farebbe usare alla BOLA interna le
    # identità di un'altra applicazione. Si archivia la cattura appena fatta e si ripristina la
    # precedente; mitmproxy, riavviato, la ricarica all'avvio. Nessun file viene cancellato.
    CAPTURE.rename(CAPTURE.with_name(f"raw_traffic.{target}.{datetime.now():%Y%m%d_%H%M%S}.json"))
    if archived is not None:
        archived.rename(CAPTURE)
        print(f"[i] Ripristinata la cattura precedente da {archived}")
    subprocess.run(["docker", "compose", "restart", "mitmproxy"], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
