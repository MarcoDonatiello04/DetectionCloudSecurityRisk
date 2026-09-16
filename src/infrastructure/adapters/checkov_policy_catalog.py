"""
Catalogo semantico delle policy Checkov.

Traduce un controllo fallito (identificativo + nome ufficiale) in una classificazione
composta da natura del rischio (EXPOSURE / HARDENING), severità di base e flag di
esposizione pubblica. Le regole risiedono in un file YAML di configurazione
(``config/scanner_configs/checkov-policy-catalog.yaml``) e non nell'adapter, così che
parole chiave e severità siano parametri dell'analisi e non costanti del codice.

In assenza del catalogo (file mancante o non leggibile) il classificatore ritorna
sempre "non classificato / MEDIUM": lo stesso esito che l'adapter produceva prima
dell'introduzione della natura, così da non alterare le pipeline esistenti.
"""

import logging
import os
from dataclasses import dataclass
from typing import Any

from src.core.config import DEFAULT_CHECKOV_POLICY_CATALOG
from src.domain.entities import FindingNature, Severity

logger = logging.getLogger("SecurityPlatform.CheckovPolicyCatalog")

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


@dataclass(frozen=True)
class PolicyClassification:
    """
    Esito della classificazione di un controllo Checkov.

    Attributes:
        nature: Natura del rischio (None se il controllo non è classificato).
        severity: Severità di base coerente con la natura.
        public_facing: True se la condizione fallita rende la risorsa raggiungibile da chiunque.
        matched_by: Regola che ha prodotto l'esito ("exact", "prefix", "keyword", "default").
    """

    nature: FindingNature | None
    severity: Severity
    public_facing: bool = False
    matched_by: str = "default"


@dataclass(frozen=True)
class _KeywordGroup:
    nature: FindingNature
    severity: Severity
    public_facing: bool
    terms: tuple[str, ...]


class CheckovPolicyCatalog:
    """
    Classificatore dei controlli Checkov basato sul catalogo YAML.

    Ordine di risoluzione: mappatura esplicita per ID, prefisso di famiglia, parole chiave
    confrontate con il nome ufficiale del controllo, esito predefinito.
    """

    def __init__(self, catalog_path: str | None = None):
        """
        Carica il catalogo dal percorso indicato (o da quello di default in configurazione).

        Args:
            catalog_path (str | None): Percorso del file YAML; se None usa il default centrale.
        """
        self._policies: dict[str, PolicyClassification] = {}
        self._prefixes: list[tuple[str, PolicyClassification]] = []
        self._keyword_groups: list[_KeywordGroup] = []
        self._unclassified_severity = Severity.MEDIUM
        self.loaded = False

        path = catalog_path or DEFAULT_CHECKOV_POLICY_CATALOG
        data = self._read_catalog(path)
        if data:
            self._load(data)
            self.loaded = True
            logger.info(
                f"📚 Catalogo policy Checkov caricato: {len(self._policies)} controlli, "
                f"{len(self._prefixes)} prefissi, {len(self._keyword_groups)} gruppi di keyword."
            )
        else:
            logger.warning(
                "Catalogo policy Checkov non disponibile: tutti i controlli saranno "
                "non classificati con severità MEDIUM."
            )

    # ─── Caricamento ─────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_path(path: str) -> str | None:
        """
        Risolve il percorso del catalogo rispetto alla directory corrente o alla radice progetto.

        Args:
            path (str): Percorso assoluto o relativo del file YAML.

        Returns:
            str | None: Il primo percorso esistente, oppure None.
        """
        candidates = [path, os.path.join(_PROJECT_ROOT, path)]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return None

    def _read_catalog(self, path: str) -> dict[str, Any] | None:
        """
        Legge e valida a grandi linee il file YAML del catalogo.

        Args:
            path (str): Percorso del file YAML.

        Returns:
            dict | None: Il contenuto del catalogo, oppure None se assente o non valido.
        """
        resolved = self._resolve_path(path)
        if not resolved:
            return None
        try:
            import yaml

            with open(resolved, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Errore nella lettura del catalogo policy Checkov '{resolved}': {e}")
            return None
        if not isinstance(data, dict):
            logger.error(f"Catalogo policy Checkov '{resolved}' non valido: atteso un mapping.")
            return None
        return data

    def _load(self, data: dict[str, Any]) -> None:
        """
        Popola le strutture interne a partire dal contenuto del catalogo.

        Args:
            data (dict): Contenuto YAML già parsato.
        """
        defaults = data.get("defaults") or {}
        self._unclassified_severity = self._parse_severity(
            defaults.get("unclassified_severity"), Severity.MEDIUM
        )

        for check_id, spec in (data.get("policies") or {}).items():
            classification = self._parse_entry(spec, matched_by="exact")
            if classification:
                self._policies[str(check_id).upper()] = classification

        for prefix, spec in (data.get("prefixes") or {}).items():
            classification = self._parse_entry(spec, matched_by="prefix")
            if classification:
                self._prefixes.append((str(prefix).upper(), classification))

        for group in data.get("keywords") or []:
            if not isinstance(group, dict):
                continue
            nature = self._parse_nature(group.get("nature"))
            raw_terms = group.get("terms") or []
            terms = tuple(str(t).lower() for t in raw_terms if str(t).strip())
            if nature is None or not terms:
                continue
            self._keyword_groups.append(
                _KeywordGroup(
                    nature=nature,
                    severity=self._parse_severity(
                        group.get("severity"), self._default_severity_for(nature)
                    ),
                    public_facing=bool(group.get("public", False)),
                    terms=terms,
                )
            )

    def _parse_entry(self, spec: Any, matched_by: str) -> PolicyClassification | None:
        """
        Converte una voce del catalogo in PolicyClassification.

        Args:
            spec (Any): Mapping con chiavi nature/severity/public.
            matched_by (str): Etichetta della regola di provenienza.

        Returns:
            PolicyClassification | None: La classificazione, o None se la voce è malformata.
        """
        if not isinstance(spec, dict):
            return None
        nature = self._parse_nature(spec.get("nature"))
        if nature is None:
            return None
        return PolicyClassification(
            nature=nature,
            severity=self._parse_severity(spec.get("severity"), self._default_severity_for(nature)),
            public_facing=bool(spec.get("public", False)),
            matched_by=matched_by,
        )

    @staticmethod
    def _parse_nature(value: Any) -> FindingNature | None:
        try:
            return FindingNature(str(value).upper()) if value else None
        except ValueError:
            logger.warning(f"Natura sconosciuta nel catalogo policy Checkov: {value!r}")
            return None

    @staticmethod
    def _parse_severity(value: Any, fallback: Severity) -> Severity:
        try:
            return Severity(str(value).upper()) if value else fallback
        except ValueError:
            logger.warning(f"Severità sconosciuta nel catalogo policy Checkov: {value!r}")
            return fallback

    @staticmethod
    def _default_severity_for(nature: FindingNature) -> Severity:
        return Severity.HIGH if nature == FindingNature.EXPOSURE else Severity.LOW

    # ─── Classificazione ─────────────────────────────────────────────────────

    def classify(self, check_id: str | None, check_name: str | None) -> PolicyClassification:
        """
        Classifica un controllo Checkov fallito.

        Args:
            check_id (str | None): Identificativo del controllo (es. CKV_AWS_20).
            check_name (str | None): Nome ufficiale del controllo, su cui operano le parole chiave.

        Returns:
            PolicyClassification: Natura, severità e flag di esposizione pubblica.
        """
        normalized_id = (check_id or "").strip().upper()

        if normalized_id in self._policies:
            return self._policies[normalized_id]

        for prefix, classification in self._prefixes:
            if normalized_id.startswith(prefix):
                return classification

        name_lower = (check_name or "").lower()
        if name_lower:
            for group in self._keyword_groups:
                if any(term in name_lower for term in group.terms):
                    return PolicyClassification(
                        nature=group.nature,
                        severity=group.severity,
                        public_facing=group.public_facing,
                        matched_by="keyword",
                    )

        return PolicyClassification(
            nature=None, severity=self._unclassified_severity, matched_by="default"
        )


_default_catalog: CheckovPolicyCatalog | None = None


def get_default_catalog() -> CheckovPolicyCatalog:
    """
    Ritorna l'istanza condivisa del catalogo di default (caricata una sola volta).

    Returns:
        CheckovPolicyCatalog: Il catalogo di default.
    """
    global _default_catalog
    if _default_catalog is None:
        _default_catalog = CheckovPolicyCatalog()
    return _default_catalog
