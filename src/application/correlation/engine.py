import logging
from typing import Any

from src.core.config import (
    CONFIDENCE_NORMALIZER,
    CONTEXT_SCORE_INTERNET_EXPOSED,
    CONTEXT_SCORE_PUBLIC_RESOURCE,
    CONTEXT_SCORE_SENSITIVE_DATA,
    DEFAULT_CONTEXT_AUTHENTICATION_AUTHORIZATION,
    DEFAULT_CONTEXT_HARDENING,
    DEFAULT_CONTEXT_OTHER,
    MAX_RISK_SCORE,
    RISK_WEIGHT_CONFIDENCE,
    RISK_WEIGHT_CONTEXT,
    RISK_WEIGHT_SEVERITY,
)
from src.domain.entities import Finding, FindingCategory, FindingNature, RuntimeEvidence, Severity
from src.normalization.normalizer import APIEndpointNormalizer

logger = logging.getLogger("SecurityPlatform.CorrelationEngine")


class RiskCorrelationEngine:
    """
    Motore di Correlazione e Scoring.
    Raggruppa i findings statici (IaC/AST) e runtime (DAST/Traffic) basandosi su chiavi
    di risorsa e path API normalizzati e calcola un punteggio di rischio complessivo pesato.

    Quando più findings condividono la stessa risorsa, la voce rappresentativa è scelta per
    natura (EXPOSURE > non classificato > HARDENING) e poi per severità, così che un'ACL
    pubblica non venga mai nascosta da una notifica mancante incontrata prima. I controlli
    assorbiti restano consultabili in ``raw_data["aggregated_checks"]``.
    """

    # Chiavi di raw_data gestite dal motore, escluse dalla copia dei dati grezzi in fase di merge
    _AGGREGATED_CHECKS_KEY = "aggregated_checks"
    _MERGED_PREFIX = "merged_"

    def __init__(self):
        """
        Inizializza il RiskCorrelationEngine impostando il dizionario dei findings correlati.
        """
        self.correlated_findings: dict[str, Finding] = {}

    def correlate(
        self, static_findings: list[Finding], runtime_findings: list[Finding]
    ) -> list[Finding]:
        """
        Unisce i findings statici e runtime in un inventario correlato.
        Se un rischio statico trova riscontro in un test o log a runtime, allega l'evidenza
        e adegua la severity ed il punteggio di rischio.

        Args:
            static_findings (List[Finding]): Lista dei Finding derivati da scansioni statiche.
            runtime_findings (List[Finding]): Lista dei Finding derivati da verifiche a runtime.

        Returns:
            List[Finding]: Lista dei Finding correlati.
        """
        self.correlated_findings = {}

        # 1. Indicizziamo prima i findings statici nel registro usando una chiave logica di risorsa
        for static_finding in static_findings:
            key = self._get_correlation_key(static_finding)
            if key not in self.correlated_findings:
                self.correlated_findings[key] = static_finding
                continue

            # Se c'è già una vulnerabilità sulla stessa risorsa, uniamo le informazioni.
            # La voce rappresentativa è quella che descrive meglio il rischio (natura, poi
            # severità), non la prima incontrata: un'esposizione prevale sempre sull'hardening.
            existing = self.correlated_findings[key]
            if self._outranks(static_finding, existing):
                logger.debug(
                    f"🔁 {key}: '{static_finding.title}' diventa la voce rappresentativa "
                    f"al posto di '{existing.title}'."
                )
                self._merge_findings(static_finding, existing)
                self.correlated_findings[key] = static_finding
            else:
                self._merge_findings(existing, static_finding)

        # 2. Correliamo con i findings di runtime
        for runtime_finding in runtime_findings:
            key = self._get_correlation_key(runtime_finding)

            if key in self.correlated_findings:
                existing = self.correlated_findings[key]
                logger.info(f"🔗 Correlazione trovata per la chiave: {key}")

                # Riscontro empirico a runtime della vulnerabilità: allega evidence. Se il
                # finding runtime non la trasporta, ne sintetizziamo una minima dal contesto
                # API, così che la conferma empirica resti sempre tracciata sulla voce.
                existing.runtime_evidence = runtime_finding.runtime_evidence or RuntimeEvidence(
                    tested_url=runtime_finding.api.endpoint if runtime_finding.api else None
                )

                # Boost della severity e confidence in quanto verificata empiricamente a runtime
                if existing.severity.score < Severity.CRITICAL.score:
                    logger.info(
                        f"🔺 Elevazione Severity per {existing.finding_id} da {existing.severity.value} a HIGH/CRITICAL per riscontro a runtime."
                    )
                    existing.severity = (
                        Severity.CRITICAL if existing.severity == Severity.HIGH else Severity.HIGH
                    )

                existing.confidence = 1.0

                # Il riscontro empirico dimostra che il rischio è sfruttabile: la natura
                # diventa esposizione anche se il finding statico era di solo hardening.
                existing.nature = runtime_finding.nature or FindingNature.EXPOSURE

                if runtime_finding.finding_id not in existing.related_findings:
                    existing.related_findings.append(runtime_finding.finding_id)

                # Uniamo dati grezzi aggiuntivi
                existing.raw_data[f"runtime_verification_{runtime_finding.finding_id}"] = (
                    runtime_finding.raw_data
                )
            else:
                runtime_finding.confidence = 0.9
                self.correlated_findings[key] = runtime_finding

        logger.info(
            f"📊 Correlazione completata: {len(self.correlated_findings)} entità di rischio elaborate."
        )
        return list(self.correlated_findings.values())

    def calculate_risk_score(self, finding: Finding) -> float:
        """
        Calcola un punteggio di rischio numerico normalizzato (0.0 - 10.0).
        Formula: (Severità * 0.6) + (Confidenza * 0.2) + (ContextMultiplier * 0.2)

        Args:
            finding (Finding): Il Finding su cui calcolare il punteggio di rischio.

        Returns:
            float: Il punteggio complessivo di rischio calcolato.
        """
        sev_score = finding.severity.score
        conf_score = finding.confidence * CONFIDENCE_NORMALIZER

        # Moltiplicatore di contesto (es: esposto a internet, dati sensibili)
        context_score = 0.0
        if finding.nature == FindingNature.HARDENING:
            # Una linea di difesa mancante non è un vettore d'accesso: nessun bonus di
            # esposizione, così un bucket privato senza log non gonfia il punteggio.
            context_score = DEFAULT_CONTEXT_HARDENING
        elif finding.risk_context:
            if finding.risk_context.internet_exposed:
                context_score += CONTEXT_SCORE_INTERNET_EXPOSED
            if finding.risk_context.sensitive_data_detected:
                context_score += CONTEXT_SCORE_SENSITIVE_DATA
            if finding.risk_context.public_resource:
                context_score += CONTEXT_SCORE_PUBLIC_RESOURCE
        else:
            # Default basato sulla categoria
            if finding.category in (FindingCategory.AUTHENTICATION, FindingCategory.AUTHORIZATION):
                context_score = DEFAULT_CONTEXT_AUTHENTICATION_AUTHORIZATION
            else:
                context_score = DEFAULT_CONTEXT_OTHER

        # Calcolo pesato
        risk_score = (
            (sev_score * RISK_WEIGHT_SEVERITY)
            + (conf_score * RISK_WEIGHT_CONFIDENCE)
            + (context_score * RISK_WEIGHT_CONTEXT)
        )
        return round(min(risk_score, MAX_RISK_SCORE), 2)

    def _get_correlation_key(self, finding: Finding) -> str:
        """
        Determina la chiave logica per raggruppare i findings in base alla risorsa target.

        Args:
            finding (Finding): Il Finding da cui estrarre o generare la chiave.

        Returns:
            str: La stringa identificativa della chiave di correlazione.
        """
        if finding.correlation_key:
            return finding.correlation_key

        # Per le API, usiamo METHOD + Path normalizzato
        if finding.api and finding.api.endpoint:
            norm_path = APIEndpointNormalizer.normalize_path(finding.api.endpoint)
            method = (finding.api.method or "GET").upper()
            return f"api:{method}:{norm_path}"

        # Per risorse cloud/IaC, usiamo il resource_id o resource_name
        if finding.resource_id:
            return f"resource:{finding.resource_id}"

        # Fallback al target localizzato (es: file e riga)
        if finding.location:
            return f"file:{finding.location.file_path}:{finding.location.start_line or 0}"

        return f"generic:{finding.finding_id}"

    @staticmethod
    def _outranks(candidate: Finding, incumbent: Finding) -> bool:
        """
        Stabilisce se ``candidate`` descrive il rischio della risorsa meglio di ``incumbent``.

        Criterio: natura (EXPOSURE < non classificato < HARDENING per rank), poi severità
        maggiore. A parità completa prevale la voce già presente (ordine deterministico).

        Args:
            candidate (Finding): Il nuovo finding sulla stessa risorsa.
            incumbent (Finding): La voce rappresentativa attuale.

        Returns:
            bool: True se il candidato deve diventare la voce rappresentativa.
        """
        if candidate.nature_rank != incumbent.nature_rank:
            return candidate.nature_rank < incumbent.nature_rank
        return candidate.severity.score > incumbent.severity.score

    @staticmethod
    def _summarize(finding: Finding) -> dict[str, Any]:
        """
        Riassunto compatto di un finding assorbito, mantenuto come sotto-elemento informativo.

        Args:
            finding (Finding): Il finding da riassumere.

        Returns:
            Dict[str, Any]: Identificativo, regola, titolo, severità e natura.
        """
        return {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "nature": finding.nature.value if finding.nature else None,
        }

    def _merge_findings(self, target: Finding, source: Finding) -> None:
        """
        Sincronizza due findings statici sulla stessa risorsa, assorbendo ``source`` in ``target``.

        Un controllo di natura inferiore (es. hardening) non altera mai la severità della voce
        rappresentativa; i controlli assorbiti sono elencati in ``raw_data["aggregated_checks"]``.

        Args:
            target (Finding): Il Finding destinazione in cui confluire i dati.
            source (Finding): Il Finding origine da cui estrarre i dati da unire.
        """
        # Se la sorgente ha severity maggiore e natura non inferiore, la eleviamo
        if (
            source.nature_rank <= target.nature_rank
            and source.severity.score > target.severity.score
        ):
            target.severity = source.severity

        # Uniamo i riferimenti, inclusi quelli che la sorgente aveva già aggregato
        for related_id in [source.finding_id, *source.related_findings]:
            if related_id != target.finding_id and related_id not in target.related_findings:
                target.related_findings.append(related_id)

        # Uniamo tag e referenze
        target.tags = list(set(target.tags + source.tags))
        target.references = list(set(target.references + source.references))

        # Sotto-elementi informativi: la sorgente e tutto ciò che aveva già assorbito
        aggregated = target.raw_data.setdefault(self._AGGREGATED_CHECKS_KEY, [])
        known_ids = {entry.get("finding_id") for entry in aggregated}
        inherited = source.raw_data.get(self._AGGREGATED_CHECKS_KEY, [])
        for entry in [self._summarize(source), *inherited]:
            entry_id = entry.get("finding_id")
            if entry_id != target.finding_id and entry_id not in known_ids:
                aggregated.append(entry)
                known_ids.add(entry_id)

        # Conserviamo dati grezzi aggiuntivi (senza duplicare le strutture di aggregazione)
        for key, value in source.raw_data.items():
            if key.startswith(self._MERGED_PREFIX) and key not in target.raw_data:
                target.raw_data[key] = value
        target.raw_data[f"{self._MERGED_PREFIX}{source.finding_id}"] = {
            key: value
            for key, value in source.raw_data.items()
            if not key.startswith(self._MERGED_PREFIX) and key != self._AGGREGATED_CHECKS_KEY
        }
