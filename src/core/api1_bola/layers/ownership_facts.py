"""
Estrazione dei fatti di autorizzazione a livello di oggetto dal corpo di un handler.

Il Layer 1 (``layer1_ast.py``) individua con tree-sitter gli handler di rotta e i loro
parametri di path; questo modulo legge il corpo dell'handler, istruzione per
istruzione, e risponde a quattro domande:

1. quale istruzione accede a un oggetto usando un ID ricevuto dal path (lookup ORM/DB,
   subscript su una collezione);
2. se, prima di quell'accesso, l'handler legge l'identità del chiamante;
3. se l'oggetto viene legato al soggetto autenticato (query filtrata sull'owner,
   confronto owner/identità, helper di ownership, decorator dedicato);
4. per i path annidati, quali ID sono validati contro l'owner e quali sono agganciati
   a un ID già validato.

L'analisi è euristica e intra-procedurale: ciò che accade in funzioni chiamate
dall'handler non è visibile (vedi ``docs/owasp_api1_coverage.md``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.core.api1_bola.models import ObjectAccess, OwnershipCheck, RouteHandler

PYTHON = "python"
JAVASCRIPT = "javascript"

# ---------------------------------------------------------------------------
# Vocabolari
# ---------------------------------------------------------------------------

# Espressioni che restituiscono l'identità del chiamante (il match copre anche
# l'attributo immediatamente successivo, così la rimozione lascia solo l'altro membro
# del confronto).
_PY_IDENTITY = [
    r"\bcurrent_user\b(?:\.\w+)?",
    r"\bg\.(?:current_)?user\b(?:\.\w+)?",
    r"\brequest\.user\b(?:\.\w+)?",
    r"\bget_jwt_identity\s*\(\s*\)",
    r"\bget_jwt\s*\(\s*\)",
    r"\bget_current_user\s*\(\s*\)(?:\.\w+)?",
    r"\bsession\s*(?:\[|\.get\s*\()\s*['\"](?:user|user_id|uid|username|sub)['\"]\s*[\])]?",
    r"\brequest\.auth\b(?:\.\w+)?",
    r"\[\s*['\"]sub['\"]\s*\]",
]
_JS_IDENTITY = [
    r"\b{req}\.user\b(?:\.\w+)?",
    r"\b{req}\.auth\b(?:\.\w+)?",
    r"\b{req}\.session\.user\w*\b(?:\.\w+)?",
    r"\b{req}\.userId\b",
    r"\b{req}\.currentUser\b(?:\.\w+)?",
    r"\bres\.locals\.user\b(?:\.\w+)?",
    r"\[\s*['\"]sub['\"]\s*\]",
]

# Funzioni che, per convenzione di nome, estraggono l'identità del chiamante dalla richiesta
# (``extract_identity(request)``, ``getCurrentUser(req)``, ``get_user_from_token(tok)``).
# Contano solo se tra gli argomenti non compare un ID di path: ``get_user(user_id)`` è un
# lookup di un utente qualsiasi, non l'identità del chiamante.
_IDENTITY_CALL = re.compile(
    r"(?i)\b(?:get|extract|current|load|fetch|resolve|decode|read|parse|authenticate)_?"
    r"(?:current_?|authenticated_?|request_?|logged_?in_?)?"
    r"(?:user|identity|principal|subject|username|caller|claims)"
    r"(?:_?(?:from_?(?:request|token|header|jwt)|info|name))?\s*\("
)

# Chiamate che leggono/scrivono un oggetto: la presenza di un ID di path tra i loro
# argomenti identifica un accesso guidato da input del client.
_PY_ACCESS_CALL = re.compile(
    r"(?:\.\s*(?:get|get_or_404|first_or_404|one_or_none|filter|filter_by|where|find|"
    r"find_one|find_by_id|select|execute|fetchone|fetch_one|delete|update|remove|pop|scalar)"
    r"|\bget_object_or_404|\bget_or_404|\bselect)\s*\("
)
_JS_ACCESS_CALL = re.compile(
    r"\.\s*(?:findById|findOne|findByPk|findUnique|findFirst|find|get|getById|where|query|"
    r"select|filter|delete|deleteOne|findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|"
    r"findOneAndDelete|update|updateOne|destroy|remove|execute)\s*\("
)

# Helper applicativi che, per convenzione di nome, verificano l'ownership.
_OWNERSHIP_HELPER = re.compile(
    r"\b(?:check_object_permissions?|check_ownership|ensure_owner(?:ship)?|assert_owner(?:ship)?"
    r"|verify_owner(?:ship)?|require_owner(?:ship)?|is_owner|authorize|can_access|has_access"
    r"|has_object_permission|enforce|checkOwnership|isOwner|ensureOwner|verifyOwnership"
    r"|assertOwnership|canAccess|authorizeResource)\s*\("
)

# Campi che, confrontati con l'identità, esprimono l'appartenenza dell'oggetto.
_OWNER_TOKEN = re.compile(
    r"(?i)(owner|user_?id\b|author|created_?by|account_?id|tenant_?id|customer_?id|"
    r"belongs_?to|\.user\b|\[\s*['\"]user['\"]\s*\])"
)

_COMPARISON = re.compile(
    r"===|!==|==|!=|\bis\b|\bin\b|\.includes\s*\(|\.indexOf\s*\(|\.some\s*\(|\.equals\s*\("
)
_CLAUSE_SPLIT = re.compile(r"\band\b|\bor\b|&&|\|\|")

# Guardie di ruolo privilegiato: l'endpoint appartiene al dominio BFLA (API5), non BOLA.
_PRIVILEGED_ROLE = re.compile(
    r"(?i)\b(?:is_admin|isAdmin|is_staff|isStaff|is_superuser|isSuperuser|admin_required|"
    r"admin_only|require_admin|requireAdmin|staff_required|superuser_required)\b"
    r"|role\w*\s*(?:===|!==|==|!=|\bin\b)\s*[\[\(]?\s*['\"](?:admin|superuser|staff|manager|"
    r"moderator)['\"]"
    r"|['\"](?:admin|superuser|staff|manager|moderator)['\"]\s*(?:===|!==|==|!=|\bin\b|\bnot in\b)"
    r"|(?:roles?_required|require_roles?|role_required|requireRole|hasRole|has_role)\s*\(\s*"
    r"['\"](?:admin|superuser|staff|manager|moderator)['\"]"
)

# Enforcement dell'autenticazione dentro il corpo (in alternativa a decorator/middleware).
_BODY_AUTH = re.compile(r"\bverify_jwt_in_request\s*\(|\bjwt\.verify\s*\(")

_NUMERIC_CAST = r"(?:\bint\s*\(|\bparseInt\s*\(|\bNumber\s*\()"


def is_privileged_guard(text: str) -> bool:
    """True se il testo (decorator, middleware o condizione) richiede un ruolo privilegiato."""
    return bool(_PRIVILEGED_ROLE.search(text))


@dataclass
class LogicalLine:
    line_number: int
    text: str


# ---------------------------------------------------------------------------
# Utility testuali
# ---------------------------------------------------------------------------


def strip_comment(line: str, language: str) -> str:
    """Rimuove il commento di fine riga ignorando i marcatori dentro le stringhe."""
    marker = "#" if language == PYTHON else "//"
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif line.startswith(marker, i):
            return line[:i].rstrip()
        i += 1
    return line.rstrip()


def mask_strings(text: str) -> str:
    """Sostituisce il contenuto dei letterali stringa con spazi, preservando le posizioni."""
    out = list(text)
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                out[i] = " "
                if i + 1 < len(text):
                    out[i + 1] = " "
                i += 2
                continue
            if ch == quote:
                quote = None
            else:
                out[i] = " "
        elif ch in ("'", '"', "`"):
            quote = ch
        i += 1
    return "".join(out)


def _bracket_delta(text: str) -> int:
    masked = mask_strings(text)
    return masked.count("(") + masked.count("[") - masked.count(")") - masked.count("]")


def logical_lines(lines: list[tuple[int, str]]) -> list[LogicalLine]:
    """
    Unisce le righe fisiche in istruzioni logiche finché parentesi tonde e quadre non
    sono bilanciate (chiamate su più righe, oggetti letterali passati come argomento).
    Le graffe non vengono contate: in JavaScript aprono i blocchi di controllo.
    """
    result: list[LogicalLine] = []
    buffer: list[str] = []
    start: int | None = None
    depth = 0
    for number, raw in lines:
        text = raw.strip()
        if not text and not buffer:
            continue
        if start is None:
            start = number
        buffer.append(text)
        depth += _bracket_delta(text)
        if depth <= 0:
            result.append(LogicalLine(start, " ".join(buffer)))
            buffer, start, depth = [], None, 0
    if buffer and start is not None:
        result.append(LogicalLine(start, " ".join(buffer)))
    return result


def _balanced_segment(text: str, open_pos: int, opening: str, closing: str) -> str:
    """Contenuto tra la parentesi in ``open_pos`` e la sua chiusura (o fine riga)."""
    masked = mask_strings(text)
    depth = 0
    for i in range(open_pos, len(text)):
        if masked[i] == opening:
            depth += 1
        elif masked[i] == closing:
            depth -= 1
            if depth == 0:
                return text[open_pos + 1 : i]
    return text[open_pos + 1 :]


def _receiver_before(text: str, pos: int) -> str:
    """Espressione (catena di attributi/subscript/chiamate) che precede ``pos``."""
    masked = mask_strings(text)
    depth = 0
    i = pos - 1
    while i >= 0:
        ch = masked[i]
        if ch in ")]":
            depth += 1
        elif ch in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and not (ch.isalnum() or ch in "_.$'\"`"):
            break
        i -= 1
    return text[i + 1 : pos]


def _destructured_names(pattern: str) -> list[tuple[str, str]]:
    """``{ a, b: c, d = 1 }`` -> [(a, a), (b, c), (d, d)] come coppie (chiave, locale)."""
    names = []
    for part in pattern.strip("{} ").split(","):
        part = part.split("=")[0].strip()
        if not part:
            continue
        if ":" in part:
            key, local = (p.strip() for p in part.split(":", 1))
        else:
            key = local = part
        if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
            names.append((key, local))
    return names


_PY_ASSIGN = re.compile(
    r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::\s*[^=]+)?=(?!=)\s*(.+)$"
)
_JS_ASSIGN = re.compile(
    r"^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*|\{[^}]*\}|\[[^\]]*\])\s*=(?!=)\s*"
    r"(?:await\s+)?(.+)$"
)
_RETURN = re.compile(r"^\s*return\s+(?:await\s+)?(.+?);?\s*$")


def _split_top_level(text: str) -> list[str]:
    """Divide per virgole di primo livello (argomenti, elementi di una tupla)."""
    masked = mask_strings(text)
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(masked):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


_ROLE_RANK = {"identity": 2, "object": 1, "none": 0}


def _merge_roles(
    current: list[tuple[str, set[str]]], new: list[tuple[str, set[str]]]
) -> list[tuple[str, set[str]]]:
    """Unisce i ruoli di più ``return``: vince l'arità maggiore, poi identity > object > none."""
    if len(new) != len(current):
        return new if len(new) > len(current) else current
    merged = []
    for (role_a, params_a), (role_b, params_b) in zip(current, new, strict=True):
        role = role_a if _ROLE_RANK[role_a] >= _ROLE_RANK[role_b] else role_b
        merged.append((role, params_a | params_b))
    return merged


def _target_names(lhs: str) -> list[str]:
    """Nomi assegnati: ``a``, ``a, b``, ``[a, b]`` (i destrutturati ``{}`` a parte)."""
    return [n.strip() for n in lhs.strip("[] ").split(",") if n.strip()]


@dataclass
class HelperSummary:
    """
    Riassunto di una funzione dello stesso file chiamata dall'handler (un livello).

    Attributes:
        params: Parametri della funzione, in ordine.
        accessed: Parametri usati per accedere a un oggetto.
        checked: Parametri il cui oggetto è legato al chiamante dentro la funzione.
        reads_identity: La funzione legge l'identità del chiamante.
        identity_before_access: L'identità è letta prima del primo accesso.
        return_roles: Per posizione del valore restituito: ("identity"|"object"|"none",
            parametri coinvolti).
    """

    params: list[str]
    accessed: set[str] = field(default_factory=set)
    checked: set[str] = field(default_factory=set)
    reads_identity: bool = False
    identity_before_access: bool = False
    return_roles: list[tuple[str, set[str]]] = field(default_factory=list)


_PY_FOR = re.compile(r"^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.+):")
_JS_FOR = re.compile(r"^\s*for\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+(.+)\)")


# ---------------------------------------------------------------------------
# Analizzatore
# ---------------------------------------------------------------------------


class _HandlerScanner:
    """Stato dell'analisi di un singolo handler (alias, oggetti, identità)."""

    def __init__(
        self,
        handler: RouteHandler,
        req_name: str,
        identity_vars: list[str],
        helpers: dict[str, HelperSummary] | None = None,
    ):
        self.h = handler
        self.helpers = helpers or {}
        self.returns: list[str] = []
        self.lang = handler.language
        self.req = re.escape(req_name or "req")
        # alias locale -> parametro di path
        self.aliases: dict[str, str] = {p: p for p in handler.id_params}
        # variabile oggetto -> parametri che l'hanno selezionata
        self.objects: dict[str, set[str]] = {}
        self.identity_vars: list[str] = list(identity_vars)
        self.link_sets: list[set[str]] = []

    # --- riconoscitori ----------------------------------------------------

    def _identity_patterns(self) -> list[str]:
        base = (
            _PY_IDENTITY
            if self.lang == PYTHON
            else [p.replace("{req}", self.req) for p in _JS_IDENTITY]
        )
        dynamic = [rf"(?<![\.\w$]){re.escape(v)}\b(?:\.\w+)?" for v in self.identity_vars]
        return base + dynamic

    def _identity_calls(self, text: str) -> list[tuple[int, int]]:
        """Span delle chiamate che estraggono l'identità (senza ID di path negli argomenti)."""
        spans = []
        masked = mask_strings(text)
        for match in _IDENTITY_CALL.finditer(masked):
            args = _balanced_segment(text, match.end() - 1, "(", ")")
            if self.refs(args):
                continue
            spans.append((match.start(), match.end() + len(args) + 1))
        return spans

    def has_identity(self, text: str) -> bool:
        if any(re.search(p, text) for p in self._identity_patterns()):
            return True
        return bool(self._identity_calls(text))

    def strip_identity(self, text: str) -> str:
        for start, end in reversed(self._identity_calls(text)):
            text = text[:start] + " " + text[end:]
        for pattern in self._identity_patterns():
            text = re.sub(pattern, " ", text)
        return text

    def refs(self, text: str) -> set[str]:
        """Parametri di path citati nel testo (direttamente o tramite alias)."""
        found: set[str] = set()
        masked = mask_strings(text)
        for alias, param in self.aliases.items():
            if re.search(rf"(?<![\.\w$]){re.escape(alias)}\b(?!\s*=(?!=))", masked):
                found.add(param)
        if self.lang == JAVASCRIPT:
            for param in self.h.id_params:
                p = re.escape(param)
                if re.search(rf"\bparams\.{p}\b|params\[\s*['\"`]{p}['\"`]\s*\]", text):
                    found.add(param)
        return found

    def object_refs(self, text: str) -> set[str]:
        """Parametri associati alle variabili oggetto citate nel testo."""
        found: set[str] = set()
        masked = mask_strings(text)
        for var, params in self.objects.items():
            if re.search(rf"(?<![\.\w$]){re.escape(var)}\b", masked):
                found |= params
        return found

    def find_accesses(self, text: str) -> list[tuple[str, str, bool, set[str]]]:
        """
        Accessi a oggetti nell'istruzione: (parametro, argomenti, scoped, parametri collegati).
        ``scoped`` è True quando l'identità compare tra gli argomenti di una chiamata della
        catena o nel ricevitore (es. ``current_user.orders.filter_by(id=order_id)``).
        """
        masked = mask_strings(text)
        pattern = _PY_ACCESS_CALL if self.lang == PYTHON else _JS_ACCESS_CALL
        calls: list[tuple[str, str]] = []
        for match in pattern.finditer(masked):
            open_pos = match.end() - 1
            calls.append(
                (
                    _balanced_segment(text, open_pos, "(", ")"),
                    _receiver_before(text, match.start()),
                )
            )
        for match in re.finditer(r"[\w\)\]]\s*\[", masked):
            open_pos = match.end() - 1
            receiver = _receiver_before(text, open_pos)
            if re.search(r"\bparams$|\bview_args$|\bargs$|\bform$|\bheaders$", receiver.strip()):
                continue
            calls.append((_balanced_segment(text, open_pos, "[", "]"), receiver))

        chain_scoped = any(
            self.has_identity(args) or self.has_identity(recv) for args, recv in calls
        )
        results: list[tuple[str, str, bool, set[str]]] = []
        seen: set[str] = set()
        for args, receiver in calls:
            params = self.refs(args)
            for param in sorted(params):
                if param in seen:
                    continue
                seen.add(param)
                linked = (
                    params
                    | self.object_refs(args)
                    | self.refs(receiver)
                    | self.object_refs(receiver)
                ) - {param}
                results.append((param, args, chain_scoped, linked))
        return results

    # --- scansione --------------------------------------------------------

    def run(self, lines: list[LogicalLine]) -> None:
        h = self.h
        identity_seen = False
        pending_all: list[OwnershipCheck] = []

        for line in lines:
            raw = line.text
            if self.has_identity(raw) and not identity_seen:
                identity_seen = True
                h.identity_evidence = raw
            if _BODY_AUTH.search(raw) and not h.has_authentication:
                h.has_authentication = True
                h.auth_evidence = raw
            if h.privileged_role_guard is None and _PRIVILEGED_ROLE.search(raw):
                h.privileged_role_guard = raw

            assign_re = _PY_ASSIGN if self.lang == PYTHON else _JS_ASSIGN
            assign = assign_re.match(raw)
            for_re = _PY_FOR if self.lang == PYTHON else _JS_FOR
            loop = for_re.match(raw)

            ret = _RETURN.match(raw)
            if ret:
                self.returns.append(ret.group(1))

            if self._apply_helper_calls(line, assign, identity_seen):
                if self.has_identity(raw) or any(
                    self.helpers[n].reads_identity for n in self._called_helpers(raw)
                ):
                    if not identity_seen:
                        identity_seen = True
                        h.identity_evidence = raw
                self._scan_comparisons(line)
                continue

            accesses = self.find_accesses(raw)
            if accesses:
                if not h.object_accesses:
                    h.identity_before_access = identity_seen
                names = _target_names(assign.group(1)) if assign else []
                lhs = names[0] if len(names) == 1 and not names[0].startswith("{") else None
                for param, _args, scoped, linked in accesses:
                    h.object_accesses.append(
                        ObjectAccess(
                            line_number=line.line_number,
                            text=raw,
                            id_param=param,
                            object_var=lhs,
                            scoped_to_identity=scoped,
                            linked_params=sorted(linked),
                        )
                    )
                    if scoped:
                        h.ownership_checks.append(
                            OwnershipCheck("scoped_query", line.line_number, raw, [param])
                        )
                    if lhs:
                        self.objects.setdefault(lhs, set()).add(param)
            elif assign:
                self._track_assignment(assign.group(1), assign.group(2))
            if loop and self.has_identity(loop.group(2)):
                self.identity_vars.append(loop.group(1))

            self._scan_comparisons(line)
            helper = _OWNERSHIP_HELPER.search(mask_strings(raw))
            if helper:
                args = _balanced_segment(raw, helper.end() - 1, "(", ")")
                covered = self.refs(args) | self.object_refs(args)
                check = OwnershipCheck("helper", line.line_number, raw, sorted(covered))
                h.ownership_checks.append(check)
                if not covered:
                    pending_all.append(check)

        accessed = h.accessed_params
        for check in pending_all:
            check.id_params = list(accessed)
        self._resolve_bindings()

    def _track_assignment(self, lhs: str, rhs: str) -> None:
        if lhs.startswith("{"):
            names = _destructured_names(lhs)
            if re.search(r"\bparams\b", rhs):
                for key, local in names:
                    if key in self.h.id_params:
                        self.aliases[local] = key
            elif self.has_identity(rhs):
                self.identity_vars.extend(local for _key, local in names)
            return
        rhs_identity = self.has_identity(rhs)
        params = self.refs(rhs)
        objects = self.object_refs(rhs)
        for name in _target_names(lhs):
            if params and not rhs_identity:
                self.aliases[name] = sorted(params)[0]
            elif objects and not rhs_identity:
                self.objects.setdefault(name, set()).update(objects)
            elif rhs_identity and not params and not objects:
                self.identity_vars.append(name)

    # --- funzioni dello stesso file (un livello) ---------------------------

    def _called_helpers(self, text: str) -> list[str]:
        masked = mask_strings(text)
        return [
            name
            for name in self.helpers
            if re.search(rf"(?<![\.\w$]){re.escape(name)}\s*\(", masked)
        ]

    def _apply_helper_calls(self, line: LogicalLine, assign, identity_seen: bool) -> bool:
        """
        Traduce una chiamata a una funzione riassunta nei fatti dell'handler: accessi agli
        oggetti fatti dentro la funzione, controlli di ownership, identità letta e ruoli dei
        valori restituiti (``username, owner, err = _load_resource("projects", id)``).
        """
        h = self.h
        raw = line.text
        handled = False
        for name in self._called_helpers(raw):
            summary = self.helpers[name]
            match = re.search(rf"(?<![\.\w$]){re.escape(name)}\s*\(", mask_strings(raw))
            if match is None:
                continue
            args = _split_top_level(_balanced_segment(raw, match.end() - 1, "(", ")"))
            bound: dict[str, set[str]] = {}
            for position, expr in enumerate(args):
                kw = re.match(r"^([A-Za-z_]\w*)\s*=(?!=)\s*(.+)$", expr)
                param = (
                    kw.group(1)
                    if kw
                    else (summary.params[position] if position < len(summary.params) else None)
                )
                value = kw.group(2) if kw else expr
                if param is not None:
                    bound[param] = self.refs(value) | self.object_refs(value)

            for helper_param, handler_params in bound.items():
                if helper_param not in summary.accessed:
                    continue
                for handler_param in sorted(handler_params):
                    if not h.object_accesses:
                        h.identity_before_access = identity_seen or summary.identity_before_access
                    scoped = helper_param in summary.checked
                    h.object_accesses.append(
                        ObjectAccess(
                            line_number=line.line_number,
                            text=raw,
                            id_param=handler_param,
                            scoped_to_identity=scoped,
                        )
                    )
                    if scoped:
                        h.ownership_checks.append(
                            OwnershipCheck("helper", line.line_number, raw, [handler_param])
                        )

            if assign:
                names = _target_names(assign.group(1))
                roles = summary.return_roles
                if len(names) == len(roles) or (len(names) == 1 and roles):
                    pairs = (
                        zip(names, roles, strict=True)
                        if len(names) == len(roles)
                        else [(names[0], ("object", set().union(*(r[1] for r in roles))))]
                    )
                    for var, (role, helper_params) in pairs:
                        mapped = set().union(*(bound.get(p, set()) for p in helper_params))
                        if role == "identity":
                            self.identity_vars.append(var)
                        elif role == "object" and mapped:
                            self.objects.setdefault(var, set()).update(mapped)
            handled = True
        return handled

    def summarize(self) -> HelperSummary:
        """Riassunto di questa scansione quando il "handler" è una funzione di supporto."""
        h = self.h
        summary = HelperSummary(
            params=list(h.id_params),
            accessed={a.id_param for a in h.object_accesses},
            checked=set(h.validated_params),
            reads_identity=h.identity_evidence is not None,
            identity_before_access=h.identity_before_access,
        )
        for expr in self.returns:
            parts = _split_top_level(expr.strip("[]()") if expr.startswith(("[", "(")) else expr)
            roles = []
            for part in parts:
                if self.has_identity(part):
                    roles.append(("identity", set()))
                    continue
                params = self.refs(part) | self.object_refs(part)
                roles.append(("object", params) if params else ("none", set()))
            summary.return_roles = _merge_roles(summary.return_roles, roles)
        return summary

    def _scan_comparisons(self, line: LogicalLine) -> None:
        raw = line.text
        if re.match(r"^\s*for\b", raw):
            return
        for clause in _CLAUSE_SPLIT.split(raw):
            if not _COMPARISON.search(mask_strings(clause)):
                continue
            if self.has_identity(clause):
                stripped = self.strip_identity(clause)
                covered = self.refs(stripped) | self.object_refs(stripped)
                if covered or _OWNER_TOKEN.search(stripped):
                    if not covered:
                        covered = set(self.h.accessed_params)
                    self.h.ownership_checks.append(
                        OwnershipCheck("comparison", line.line_number, raw, sorted(covered))
                    )
            else:
                linked = self.refs(clause) | self.object_refs(clause)
                if len(linked) >= 2:
                    self.link_sets.append(linked)

    def _resolve_bindings(self) -> None:
        h = self.h
        validated: set[str] = set()
        for check in h.ownership_checks:
            validated |= set(check.id_params)
        bound = set(validated)
        changed = True
        while changed:
            changed = False
            for access in h.object_accesses:
                if access.id_param in bound:
                    continue
                if access.scoped_to_identity or bound & set(access.linked_params):
                    bound.add(access.id_param)
                    changed = True
            for link in self.link_sets:
                if bound & link and not link <= bound:
                    bound |= link
                    changed = True
        h.validated_params = [p for p in h.id_params if p in validated]
        h.bound_params = [p for p in h.id_params if p in bound]


def summarize_helper(
    name: str,
    params: list[str],
    body_lines: list[tuple[int, str]],
    language: str,
    req_name: str = "req",
) -> HelperSummary:
    """
    Riassume una funzione di supporto dello stesso file trattandone i parametri come
    possibili ID: quali usa per accedere a oggetti, quali lega al chiamante, se legge
    l'identità e che cosa restituisce. Le funzioni chiamate a loro volta non vengono
    espanse (un solo livello).
    """
    pseudo = RouteHandler(
        file_path="",
        line_number=0,
        function_name=name,
        path="",
        http_methods=[],
        language=language,
        id_params=list(params),
    )
    lines = [(n, strip_comment(t, language)) for n, t in body_lines]
    scanner = _HandlerScanner(pseudo, req_name, [])
    scanner.run(logical_lines(lines))
    return scanner.summarize()


def analyze_handler(
    handler: RouteHandler,
    body_lines: list[tuple[int, str]],
    req_name: str = "req",
    identity_vars: list[str] | None = None,
    helpers: dict[str, HelperSummary] | None = None,
) -> RouteHandler:
    """
    Riempie i fatti di autorizzazione di ``handler`` leggendo il corpo della funzione.

    Args:
        handler: Handler con path, metodi, parametri ID e guardie già estratti dal Layer 1.
        body_lines: Righe del corpo come coppie (numero di riga assoluto, testo).
        req_name: Nome del parametro request negli handler Express.
        identity_vars: Variabili che contengono l'identità per costruzione
            (es. parametri FastAPI iniettati con ``Depends(get_current_user)``).
        helpers: Riassunti delle funzioni dello stesso file chiamabili dall'handler.

    Returns:
        RouteHandler: Lo stesso handler, con accessi, controlli di ownership e binding.
    """
    lines = [(n, strip_comment(t, handler.language)) for n, t in body_lines]
    own_name = {handler.function_name}
    usable = {k: v for k, v in (helpers or {}).items() if k not in own_name}
    scanner = _HandlerScanner(handler, req_name, identity_vars or [], usable)
    scanner.run(logical_lines(lines))
    _detect_numeric_casts(handler, lines)
    return handler


def _detect_numeric_casts(handler: RouteHandler, lines: list[tuple[int, str]]) -> None:
    """Un ID convertito in intero nel corpo è sequenziale quanto uno tipizzato nel path."""
    body = "\n".join(text for _n, text in lines)
    for param in handler.id_params:
        if param in handler.numeric_id_params:
            continue
        p = re.escape(param)
        if re.search(rf"{_NUMERIC_CAST}\s*(?:\w+\.)*(?:params\.)?{p}\b", body):
            handler.numeric_id_params.append(param)
